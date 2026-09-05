// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  SRv6 L2 tunnel device (srl2)
 *
 *  A virtual Ethernet device that encapsulates L2 frames in IPv6 with a
 *  Segment Routing Header (SRH) for transmission over an SRv6 network.
 *  On the remote side, a seg6_local behavior such as End.DT2U or End.DX2
 *  decapsulates the inner Ethernet frame for L2 delivery.
 *
 *  The encapsulation logic reuses seg6_do_srh_encap() from seg6_iptunnel.c
 *  with IPPROTO_ETHERNET (143). The transmit path uses the standard IPv6
 *  tunnel infrastructure (dst_cache, ip6_route_output, ip6tunnel_xmit).
 *
 *  Authors:
 *	Andrea Mayer <andrea.mayer@uniroma2.it>
 *	Stefano Salsano <stefano.salsano@uniroma2.it>
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rhashtable.h>
#include <net/dst_cache.h>
#include <net/ip6_route.h>
#include <net/ip_tunnels.h>
#include <net/ip6_tunnel.h>
#include <net/seg6.h>
#include <linux/seg6.h>
#include <linux/srl2.h>

/* Conservative initial estimate for SRH size before newlink provides
 * the actual value. 256 bytes accommodates up to 15 SIDs.
 */
#define SRL2_SRH_HEADROOM_EST	256

struct srl2_rdst {
	struct ipv6_sr_hdr	*srh;
	struct dst_cache	dst_cache;
};

struct srl2_priv {
	struct srl2_rdst default_dst;
	struct rhashtable fdb;
	/* RTNL serializes writers; the list provides stable dump ordering. */
	struct list_head fdb_list;
};

struct srl2_fdb {
	struct rhash_head rhnode;
	struct list_head list;
	struct rcu_head rcu;
	u8 addr[ETH_ALEN];
	u16 state;
	struct srl2_rdst remote;
};

static const struct rhashtable_params srl2_fdb_rht_params = {
	.head_offset = offsetof(struct srl2_fdb, rhnode),
	.key_offset = offsetof(struct srl2_fdb, addr),
	.key_len = ETH_ALEN,
	.automatic_shrinking = true,
};

static struct srl2_fdb *srl2_fdb_lookup(struct srl2_priv *priv,
					const unsigned char *addr)
{
	return rhashtable_lookup_fast(&priv->fdb, addr, srl2_fdb_rht_params);
}

static int srl2_srh_validate(struct nlattr *attr,
			     struct netlink_ext_ack *extack)
{
	struct ipv6_sr_hdr *srh;

	if (!attr) {
		NL_SET_ERR_MSG(extack, "SRH with segment list is required");
		return -EINVAL;
	}

	srh = nla_data(attr);
	if (nla_len(attr) < sizeof(*srh) + sizeof(struct in6_addr) ||
	    !seg6_validate_srh(srh, nla_len(attr), false)) {
		NL_SET_ERR_MSG_ATTR(extack, attr, "Invalid SRH");
		return -EINVAL;
	}

	return 0;
}

static void srl2_fdb_free(struct srl2_fdb *fdb)
{
	dst_cache_destroy(&fdb->remote.dst_cache);
	kfree(fdb->remote.srh);
	kfree(fdb);
}

static void srl2_fdb_free_rcu(struct rcu_head *rcu)
{
	srl2_fdb_free(container_of(rcu, struct srl2_fdb, rcu));
}

static int srl2_fdb_info(struct sk_buff *skb, struct net_device *dev,
			 struct srl2_fdb *fdb, u32 portid, u32 seq,
			 int type, int flags)
{
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;

	nlh = nlmsg_put(skb, portid, seq, type, sizeof(*ndm), flags);
	if (!nlh)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	memset(ndm, 0, sizeof(*ndm));
	ndm->ndm_family = AF_BRIDGE;
	ndm->ndm_ifindex = dev->ifindex;
	ndm->ndm_state = fdb->state;
	ndm->ndm_flags = NTF_SELF;
	ndm->ndm_type = RTN_UNICAST;

	if (nla_put(skb, NDA_LLADDR, ETH_ALEN, fdb->addr) ||
	    nla_put(skb, NDA_SRL2_SRH, ipv6_optlen(fdb->remote.srh),
		    fdb->remote.srh)) {
		nlmsg_cancel(skb, nlh);
		return -EMSGSIZE;
	}

	nlmsg_end(skb, nlh);
	return 0;
}

static void srl2_fdb_notify(struct net_device *dev, struct srl2_fdb *fdb,
			    int type)
{
	struct net *net = dev_net(dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;
	size_t size;

	size = NLMSG_ALIGN(sizeof(struct ndmsg)) + nla_total_size(ETH_ALEN) +
	       nla_total_size(ipv6_optlen(fdb->remote.srh));
	skb = nlmsg_new(size, GFP_KERNEL);
	if (!skb)
		goto errout;

	err = srl2_fdb_info(skb, dev, fdb, 0, 0, type, 0);
	if (err) {
		kfree_skb(skb);
		goto errout;
	}

	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_KERNEL);
	return;
errout:
	rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}

static int srl2_fdb_validate(struct nlattr *tb[], const unsigned char *addr,
			     u16 vid, struct netlink_ext_ack *extack)
{
	int i;

	if (!is_valid_ether_addr(addr)) {
		NL_SET_ERR_MSG(extack, "Only nonzero unicast MAC addresses are supported");
		return -EINVAL;
	}
	if (vid) {
		NL_SET_ERR_MSG(extack, "VLAN-qualified FDB entries are not supported");
		return -EOPNOTSUPP;
	}
	for (i = 0; i <= NDA_MAX; i++) {
		if (!tb[i] || i == NDA_LLADDR || i == NDA_SRL2_SRH)
			continue;
		NL_SET_ERR_MSG_ATTR(extack, tb[i], "Unsupported srl2 FDB attribute");
		return -EOPNOTSUPP;
	}
	return 0;
}

static int srl2_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr,
			u16 vid, u16 flags, bool *notified,
			struct netlink_ext_ack *extack)
{
	struct srl2_priv *priv = netdev_priv(dev);
	struct srl2_fdb *old, *fdb;
	unsigned int max_mtu;
	int err, srhlen;

	ASSERT_RTNL();
	err = srl2_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;
	if (flags & NLM_F_APPEND || ndm->ndm_flags & ~NTF_SELF) {
		NL_SET_ERR_MSG(extack, "Unsupported srl2 FDB flags");
		return -EOPNOTSUPP;
	}
	if (!(ndm->ndm_state & (NUD_PERMANENT | NUD_REACHABLE)) ||
	    ndm->ndm_state & ~(NUD_PERMANENT | NUD_REACHABLE | NUD_NOARP)) {
		NL_SET_ERR_MSG(extack, "Only static FDB entries are supported");
		return -EINVAL;
	}
	err = srl2_srh_validate(tb[NDA_SRL2_SRH], extack);
	if (err)
		return err;

	old = srl2_fdb_lookup(priv, addr);
	if (old && flags & NLM_F_EXCL)
		return -EEXIST;
	if (!old && !(flags & NLM_F_CREATE))
		return -ENOENT;
	if (old && !(flags & NLM_F_REPLACE))
		return -EEXIST;

	srhlen = nla_len(tb[NDA_SRL2_SRH]);
	max_mtu = IP_MAX_MTU - sizeof(struct ipv6hdr) - srhlen - ETH_HLEN;
	if (dev->mtu > max_mtu) {
		NL_SET_ERR_MSG(extack, "Device MTU is too large for this SRH");
		return -EINVAL;
	}

	fdb = kzalloc(sizeof(*fdb), GFP_KERNEL);
	if (!fdb)
		return -ENOMEM;
	fdb->remote.srh = nla_memdup(tb[NDA_SRL2_SRH], GFP_KERNEL);
	if (!fdb->remote.srh) {
		err = -ENOMEM;
		goto free;
	}
	err = dst_cache_init(&fdb->remote.dst_cache, GFP_KERNEL);
	if (err)
		goto free;
	ether_addr_copy(fdb->addr, addr);
	fdb->state = ndm->ndm_state;

	if (old)
		err = rhashtable_replace_fast(&priv->fdb, &old->rhnode,
					      &fdb->rhnode, srl2_fdb_rht_params);
	else
		err = rhashtable_lookup_insert_fast(&priv->fdb, &fdb->rhnode,
						    srl2_fdb_rht_params);
	if (err)
		goto free;

	if (old) {
		list_replace_rcu(&old->list, &fdb->list);
		call_rcu(&old->rcu, srl2_fdb_free_rcu);
	} else {
		list_add_tail_rcu(&fdb->list, &priv->fdb_list);
	}
	/* Headroom is a hint: seg6_do_srh_encap() expands each skb as needed.
	 * Keep the maximum overhead even after deleting a longer policy.
	 */
	WRITE_ONCE(dev->needed_headroom,
		   max_t(unsigned int, dev->needed_headroom,
			 LL_MAX_HEADER + sizeof(struct ipv6hdr) + srhlen));
	dev->max_mtu = min(dev->max_mtu, max_mtu);
	srl2_fdb_notify(dev, fdb, RTM_NEWNEIGH);
	*notified = true;
	return 0;
free:
	srl2_fdb_free(fdb);
	return err;
}

static void srl2_fdb_remove(struct srl2_priv *priv, struct srl2_fdb *fdb)
{
	rhashtable_remove_fast(&priv->fdb, &fdb->rhnode, srl2_fdb_rht_params);
	list_del_rcu(&fdb->list);
	call_rcu(&fdb->rcu, srl2_fdb_free_rcu);
}

static int srl2_fdb_del(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr,
			u16 vid, bool *notified, struct netlink_ext_ack *extack)
{
	struct srl2_priv *priv = netdev_priv(dev);
	struct srl2_fdb *fdb;
	int err;

	ASSERT_RTNL();
	err = srl2_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;
	if (ndm->ndm_flags & ~NTF_SELF)
		return -EOPNOTSUPP;
	if (tb[NDA_SRL2_SRH]) {
		err = srl2_srh_validate(tb[NDA_SRL2_SRH], extack);
		if (err)
			return err;
	}
	fdb = srl2_fdb_lookup(priv, addr);
	if (!fdb)
		return -ENOENT;
	if (tb[NDA_SRL2_SRH] &&
	    (nla_len(tb[NDA_SRL2_SRH]) != ipv6_optlen(fdb->remote.srh) ||
	     memcmp(nla_data(tb[NDA_SRL2_SRH]), fdb->remote.srh,
		    ipv6_optlen(fdb->remote.srh))))
		return -ENOENT;

	srl2_fdb_notify(dev, fdb, RTM_DELNEIGH);
	srl2_fdb_remove(priv, fdb);
	*notified = true;
	return 0;
}

static int srl2_fdb_dump(struct sk_buff *skb, struct netlink_callback *cb,
			 struct net_device *dev, struct net_device *filter_dev,
			 int *idx)
{
	struct ndo_fdb_dump_context *ctx = (void *)cb->ctx;
	struct srl2_priv *priv = netdev_priv(dev);
	struct srl2_fdb *fdb;
	int err = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(fdb, &priv->fdb_list, list) {
		if (*idx >= ctx->fdb_idx) {
			err = srl2_fdb_info(skb, dev, fdb,
					    NETLINK_CB(cb->skb).portid,
					    cb->nlh->nlmsg_seq, RTM_NEWNEIGH,
					    NLM_F_MULTI);
			if (err)
				break;
		}
		++*idx;
	}
	rcu_read_unlock();
	return err;
}

static int srl2_fdb_get(struct sk_buff *skb, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr,
			u16 vid, u32 portid, u32 seq, struct netlink_ext_ack *extack)
{
	struct srl2_priv *priv = netdev_priv(dev);
	struct srl2_fdb *fdb;
	int err;

	err = srl2_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;
	rcu_read_lock();
	fdb = srl2_fdb_lookup(priv, addr);
	err = fdb ? srl2_fdb_info(skb, dev, fdb, portid, seq,
				  RTM_NEWNEIGH, 0) : -ENOENT;
	rcu_read_unlock();
	return err;
}

/*
 * srl2_xmit_one - encapsulate an L2 frame in IPv6+SRH and transmit
 *
 * When the bridge (or local stack) sends a frame through this device,
 * skb->data points to the inner Ethernet header.  We look up a route
 * towards the first SID, prepend the outer IPv6+SRH via
 * seg6_do_srh_encap(), and transmit via ip6tunnel_xmit().
 *
 * The route lookup result is cached per-cpu in dst_cache. Since the
 * first SID is constant for the lifetime of the policy, the cache
 * avoids repeated route lookups in the common case.
 */
static netdev_tx_t srl2_xmit_one(struct sk_buff *skb, struct net_device *dev,
				 struct srl2_rdst *rdst)
{
	struct net *net = dev_net(dev);
	struct dst_entry *dst;
	struct flowi6 fl6;
	int err;

	local_bh_disable();
	dst = dst_cache_get(&rdst->dst_cache);
	local_bh_enable();

	if (unlikely(!dst)) {
		memset(&fl6, 0, sizeof(fl6));
		fl6.daddr = rdst->srh->segments[rdst->srh->first_segment];

		dst = ip6_route_output(net, NULL, &fl6);
		if (dst->error) {
			dst_release(dst);
			DEV_STATS_INC(dev, tx_carrier_errors);
			goto drop;
		}

		if (dst_dev(dst) == dev) {
			dst_release(dst);
			DEV_STATS_INC(dev, collisions);
			goto drop;
		}

		local_bh_disable();
		/* saddr is unused */
		dst_cache_set_ip6(&rdst->dst_cache, dst, &fl6.saddr);
		local_bh_enable();
	}

	skb_scrub_packet(skb, false);

	skb_dst_set(skb, dst);

	err = seg6_do_srh_encap(skb, rdst->srh, IPPROTO_ETHERNET);
	if (unlikely(err)) {
		DEV_STATS_INC(dev, tx_errors);
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	skb->protocol = htons(ETH_P_IPV6);

	ip6tunnel_xmit(NULL, skb, dev, 0);

	return NETDEV_TX_OK;

drop:
	DEV_STATS_INC(dev, tx_dropped);
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static netdev_tx_t srl2_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct srl2_priv *priv = netdev_priv(dev);
	struct srl2_rdst *rdst = &priv->default_dst;
	struct srl2_fdb *fdb;

	if (unlikely(!pskb_may_pull(skb, ETH_HLEN)))
		goto drop;

	rcu_read_lock();
	fdb = srl2_fdb_lookup(priv, skb->data);
	if (fdb)
		rdst = &fdb->remote;
	if (rdst->srh) {
		srl2_xmit_one(skb, dev, rdst);
		rcu_read_unlock();
		return NETDEV_TX_OK;
	}
	rcu_read_unlock();
drop:
	DEV_STATS_INC(dev, tx_dropped);
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int srl2_dev_init(struct net_device *dev)
{
	struct srl2_priv *priv = netdev_priv(dev);
	int err;

	INIT_LIST_HEAD(&priv->fdb_list);
	err = rhashtable_init(&priv->fdb, &srl2_fdb_rht_params);
	if (err)
		return err;
	err = dst_cache_init(&priv->default_dst.dst_cache, GFP_KERNEL);
	if (err)
		rhashtable_destroy(&priv->fdb);
	return err;
}

static void srl2_dev_uninit(struct net_device *dev)
{
	struct srl2_priv *priv = netdev_priv(dev);
	struct srl2_fdb *fdb, *tmp;

	list_for_each_entry_safe(fdb, tmp, &priv->fdb_list, list)
		srl2_fdb_remove(priv, fdb);
	rhashtable_destroy(&priv->fdb);
	dst_cache_destroy(&priv->default_dst.dst_cache);
}

static void srl2_dev_free(struct net_device *dev)
{
	struct srl2_priv *priv = netdev_priv(dev);

	kfree(priv->default_dst.srh);
	priv->default_dst.srh = NULL;
}

static const struct net_device_ops srl2_netdev_ops = {
	.ndo_init		= srl2_dev_init,
	.ndo_uninit		= srl2_dev_uninit,
	.ndo_start_xmit		= srl2_xmit,
	.ndo_fdb_add		= srl2_fdb_add,
	.ndo_fdb_del		= srl2_fdb_del,
	.ndo_fdb_dump		= srl2_fdb_dump,
	.ndo_fdb_get		= srl2_fdb_get,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

static void srl2_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &srl2_netdev_ops;
	dev->needs_free_netdev = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_DSTATS;
	dev->needed_headroom = LL_MAX_HEADER + sizeof(struct ipv6hdr) +
			       SRL2_SRH_HEADROOM_EST;

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	dev->lltx = true;

	eth_hw_addr_random(dev);
}

static const struct nla_policy srl2_policy[IFLA_SRL2_MAX + 1] = {
	[IFLA_SRL2_SRH]	= { .type = NLA_BINARY },
};

static int srl2_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (data && data[IFLA_SRL2_SRH])
		return srl2_srh_validate(data[IFLA_SRL2_SRH], extack);
	return 0;
}

static int srl2_newlink(struct net_device *dev,
			struct rtnl_newlink_params *params,
			struct netlink_ext_ack *extack)
{
	struct srl2_priv *priv = netdev_priv(dev);
	struct nlattr **data = params->data;
	int srhlen = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr);
	int err;

	if (data && data[IFLA_SRL2_SRH])
		srhlen = nla_len(data[IFLA_SRL2_SRH]);
	dev->needed_headroom = LL_MAX_HEADER + sizeof(struct ipv6hdr) + srhlen;

	/* mtu describes the inner L3 payload, including neither Ethernet
	 * nor the outer IPv6/SRH headers. Longer FDB policies increase the
	 * headroom hint and lower max_mtu, without changing the current MTU.
	 */
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = IP_MAX_MTU - sizeof(struct ipv6hdr) - srhlen - ETH_HLEN;
	if (!params->tb[IFLA_MTU])
		dev->mtu = max_t(int, ETH_MIN_MTU, ETH_DATA_LEN -
				sizeof(struct ipv6hdr) - srhlen - ETH_HLEN);
	if (dev->mtu > dev->max_mtu) {
		NL_SET_ERR_MSG(extack, "Device MTU is too large for this SRH");
		return -EINVAL;
	}

	if (data && data[IFLA_SRL2_SRH]) {
		priv->default_dst.srh = nla_memdup(data[IFLA_SRL2_SRH], GFP_KERNEL);
		if (!priv->default_dst.srh)
			return -ENOMEM;
	}
	dev->priv_destructor = srl2_dev_free;
	err = register_netdevice(dev);
	/* Early registration failures do not invoke the private destructor.
	 * Later failures may already have done so; the destructor clears srh.
	 * An unregister in progress retains ownership until its destructor.
	 */
	if (err && dev->reg_state == NETREG_UNINITIALIZED)
		srl2_dev_free(dev);
	return err;
}

static void srl2_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}

static size_t srl2_get_size(const struct net_device *dev)
{
	const struct srl2_priv *priv = netdev_priv(dev);

	return priv->default_dst.srh ?
		nla_total_size(ipv6_optlen(priv->default_dst.srh)) : 0;
}

static int srl2_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct srl2_priv *priv = netdev_priv(dev);
	struct ipv6_sr_hdr *srh = priv->default_dst.srh;

	if (srh && nla_put(skb, IFLA_SRL2_SRH, ipv6_optlen(srh), srh))
		return -EMSGSIZE;

	return 0;
}

static struct rtnl_link_ops srl2_link_ops __read_mostly = {
	.kind		= "srl2",
	.maxtype	= IFLA_SRL2_MAX,
	.policy		= srl2_policy,
	.priv_size	= sizeof(struct srl2_priv),
	.setup		= srl2_setup,
	.validate	= srl2_validate,
	.newlink	= srl2_newlink,
	.dellink	= srl2_dellink,
	.get_size	= srl2_get_size,
	.fill_info	= srl2_fill_info,
};

static int __init srl2_init(void)
{
	return rtnl_link_register(&srl2_link_ops);
}

static void __exit srl2_exit(void)
{
	rtnl_link_unregister(&srl2_link_ops);
	/* FDB callbacks execute module code and may outlive the netdevice. */
	rcu_barrier();
}

module_init(srl2_init);
module_exit(srl2_exit);

MODULE_AUTHOR("Andrea Mayer <andrea.mayer@uniroma2.it>");
MODULE_AUTHOR("Stefano Salsano <stefano.salsano@uniroma2.it>");
MODULE_DESCRIPTION("SRv6 L2 tunnel device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("srl2");
