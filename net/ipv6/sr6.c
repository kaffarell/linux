// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  SRv6 L2 tunnel device (sr6)
 *
 *  A virtual Ethernet device that encapsulates L2 frames in IPv6 with a Segment
 *  Routing Header (SRH) for transmission over an SRv6 network. On the remote
 *  side, a seg6_local behavior such as End.DT2U or End.DX2 decapsulates the
 *  inner Ethernet frame for L2 delivery.
 *
 *  The encapsulation logic reuses seg6_do_srh_encap() and, for the reduced
 *  SRH encoding, seg6_do_srh_encap_red() from seg6_iptunnel.c, both with
 *  IPPROTO_ETHERNET (143). The transmit path uses dst_cache and
 *  ip6_route_output for routing, with a custom xmit helper for stats.
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
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/l3mdev.h>
#include <net/ip_tunnels.h>
#include <net/ip6_tunnel.h>
#include <net/seg6.h>
#include <net/sr6.h>
#include <linux/seg6.h>
#include <linux/if_link.h>

/* Conservative initial estimate for SRH size before newlink provides the actual
 * value. 256 bytes accommodates up to 15 SIDs.
 */
#define SR6_SRH_HEADROOM_EST	256

struct sr6_rdst {
	struct ipv6_sr_hdr	*srh;
	struct dst_cache	dst_cache;
};

struct sr6_priv {
	struct sr6_rdst		default_dst;
	struct rhashtable	fdb;
	/* RTNL serializes writers; the list provides stable dump ordering. */
	struct list_head	fdb_list;
	u32			fib_table;
	u8			encap_mode;
};

/* SRH length for the given encapsulation mode. The full mode keeps the
 * configured SRH. The reduced one drops its first SID, or drops the SRH
 * entirely when it carries no other info.
 */
static int sr6_encap_srhlen(const struct ipv6_sr_hdr *srh, u8 encap_mode)
{
	int srhlen = ipv6_optlen(srh);

	if (encap_mode != SR6_ENCAP_MODE_REDUCED)
		return srhlen;

	if (seg6_encap_red_can_skip_srh(srh))
		return 0;

	/* the first SID is not repeated, unless it is the only one */
	return srh->first_segment ? srhlen - sizeof(struct in6_addr) : srhlen;
}

struct sr6_fdb {
	struct rhash_head rhnode;
	struct list_head list;
	struct rcu_head rcu;
	u8 addr[ETH_ALEN];
	u16 state;
	struct sr6_rdst remote;
};

static const struct rhashtable_params sr6_fdb_rht_params = {
	.head_offset = offsetof(struct sr6_fdb, rhnode),
	.key_offset = offsetof(struct sr6_fdb, addr),
	.key_len = ETH_ALEN,
	.automatic_shrinking = true,
};

static struct sr6_fdb *sr6_fdb_lookup(struct sr6_priv *priv,
				      const unsigned char *addr)
{
	return rhashtable_lookup_fast(&priv->fdb, addr, sr6_fdb_rht_params);
}

static int sr6_srh_validate(struct nlattr *attr,
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

static void sr6_fdb_free(struct sr6_fdb *fdb)
{
	dst_cache_destroy(&fdb->remote.dst_cache);
	kfree(fdb->remote.srh);
	kfree(fdb);
}

static void sr6_fdb_free_rcu(struct rcu_head *rcu)
{
	sr6_fdb_free(container_of(rcu, struct sr6_fdb, rcu));
}

static int sr6_fdb_info(struct sk_buff *skb, struct net_device *dev,
			struct sr6_fdb *fdb, u32 portid, u32 seq,
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
	    nla_put(skb, NDA_SR6_SRH, ipv6_optlen(fdb->remote.srh),
		    fdb->remote.srh)) {
		nlmsg_cancel(skb, nlh);
		return -EMSGSIZE;
	}

	nlmsg_end(skb, nlh);
	return 0;
}

static void sr6_fdb_notify(struct net_device *dev, struct sr6_fdb *fdb,
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

	err = sr6_fdb_info(skb, dev, fdb, 0, 0, type, 0);
	if (err) {
		kfree_skb(skb);
		goto errout;
	}

	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_KERNEL);
	return;
errout:
	rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}

static int sr6_fdb_validate(struct nlattr *tb[], const unsigned char *addr,
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
		if (!tb[i] || i == NDA_LLADDR || i == NDA_SR6_SRH)
			continue;
		NL_SET_ERR_MSG_ATTR(extack, tb[i], "Unsupported sr6 FDB attribute");
		return -EOPNOTSUPP;
	}
	return 0;
}

static int sr6_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
		       struct net_device *dev, const unsigned char *addr,
		       u16 vid, u16 flags, bool *notified,
		       struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_fdb *old, *fdb;
	unsigned int max_mtu;
	int err, srhlen;

	ASSERT_RTNL();
	err = sr6_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;
	if (flags & NLM_F_APPEND || ndm->ndm_flags & ~NTF_SELF) {
		NL_SET_ERR_MSG(extack, "Unsupported sr6 FDB flags");
		return -EOPNOTSUPP;
	}
	if (!(ndm->ndm_state & (NUD_PERMANENT | NUD_REACHABLE)) ||
	    ndm->ndm_state & ~(NUD_PERMANENT | NUD_REACHABLE | NUD_NOARP)) {
		NL_SET_ERR_MSG(extack, "Only static FDB entries are supported");
		return -EINVAL;
	}
	err = sr6_srh_validate(tb[NDA_SR6_SRH], extack);
	if (err)
		return err;

	old = sr6_fdb_lookup(priv, addr);
	if (old && flags & NLM_F_EXCL)
		return -EEXIST;
	if (!old && !(flags & NLM_F_CREATE))
		return -ENOENT;
	if (old && !(flags & NLM_F_REPLACE))
		return -EEXIST;

	srhlen = sr6_encap_srhlen(nla_data(tb[NDA_SR6_SRH]), priv->encap_mode);
	max_mtu = IP_MAX_MTU - sizeof(struct ipv6hdr) - srhlen - ETH_HLEN;
	if (dev->mtu > max_mtu) {
		NL_SET_ERR_MSG(extack, "Device MTU is too large for this SRH");
		return -EINVAL;
	}

	fdb = kzalloc(sizeof(*fdb), GFP_KERNEL);
	if (!fdb)
		return -ENOMEM;
	fdb->remote.srh = nla_memdup(tb[NDA_SR6_SRH], GFP_KERNEL);
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
					      &fdb->rhnode, sr6_fdb_rht_params);
	else
		err = rhashtable_lookup_insert_fast(&priv->fdb, &fdb->rhnode,
						    sr6_fdb_rht_params);
	if (err)
		goto free;

	if (old) {
		list_replace_rcu(&old->list, &fdb->list);
		call_rcu(&old->rcu, sr6_fdb_free_rcu);
	} else {
		list_add_tail_rcu(&fdb->list, &priv->fdb_list);
	}
	/* Headroom is a hint: the encapsulation helpers expand each skb as
	 * needed. Keep the maximum overhead after deleting a longer policy.
	 */
	WRITE_ONCE(dev->needed_headroom,
		   max_t(unsigned int, dev->needed_headroom,
			 LL_MAX_HEADER + sizeof(struct ipv6hdr) + srhlen));
	dev->max_mtu = min(dev->max_mtu, max_mtu);
	sr6_fdb_notify(dev, fdb, RTM_NEWNEIGH);
	*notified = true;
	return 0;
free:
	sr6_fdb_free(fdb);
	return err;
}

static void sr6_fdb_remove(struct sr6_priv *priv, struct sr6_fdb *fdb)
{
	rhashtable_remove_fast(&priv->fdb, &fdb->rhnode, sr6_fdb_rht_params);
	list_del_rcu(&fdb->list);
	call_rcu(&fdb->rcu, sr6_fdb_free_rcu);
}

static int sr6_fdb_del(struct ndmsg *ndm, struct nlattr *tb[],
		       struct net_device *dev, const unsigned char *addr,
		       u16 vid, bool *notified, struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_fdb *fdb;
	int err;

	ASSERT_RTNL();
	err = sr6_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;
	if (ndm->ndm_flags & ~NTF_SELF)
		return -EOPNOTSUPP;
	if (tb[NDA_SR6_SRH]) {
		err = sr6_srh_validate(tb[NDA_SR6_SRH], extack);
		if (err)
			return err;
	}
	fdb = sr6_fdb_lookup(priv, addr);
	if (!fdb)
		return -ENOENT;
	if (tb[NDA_SR6_SRH] &&
	    (nla_len(tb[NDA_SR6_SRH]) != ipv6_optlen(fdb->remote.srh) ||
	     memcmp(nla_data(tb[NDA_SR6_SRH]), fdb->remote.srh,
		    ipv6_optlen(fdb->remote.srh))))
		return -ENOENT;

	sr6_fdb_notify(dev, fdb, RTM_DELNEIGH);
	sr6_fdb_remove(priv, fdb);
	*notified = true;
	return 0;
}

static int sr6_fdb_dump(struct sk_buff *skb, struct netlink_callback *cb,
			struct net_device *dev, struct net_device *filter_dev,
			int *idx)
{
	struct ndo_fdb_dump_context *ctx = (void *)cb->ctx;
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_fdb *fdb;
	int err = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(fdb, &priv->fdb_list, list) {
		if (*idx >= ctx->fdb_idx) {
			err = sr6_fdb_info(skb, dev, fdb,
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

static int sr6_fdb_get(struct sk_buff *skb, struct nlattr *tb[],
		       struct net_device *dev, const unsigned char *addr,
		       u16 vid, u32 portid, u32 seq, struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_fdb *fdb;
	int err;

	err = sr6_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;
	rcu_read_lock();
	fdb = sr6_fdb_lookup(priv, addr);
	err = fdb ? sr6_fdb_info(skb, dev, fdb, portid, seq,
				 RTM_NEWNEIGH, 0) : -ENOENT;
	rcu_read_unlock();
	return err;
}

/* Transmit an encapsulated frame and account for it.
 *
 * The payload length comes from the caller, which saves skb->len before the
 * encapsulation. sr6 carries Ethernet frames and, like the L2ENCAP mode in
 * seg6_iptunnel.c, has no GSO type to hand iptunnel_handle_offloads(), so the
 * inner network offset that ip6tunnel_xmit() derives the length from is never
 * set here.
 *
 * An sr6 device can end up routed over itself, so the transmit is guarded
 * against a routing loop; see IP_TUNNEL_RECURSION_LIMIT.
 */
static void sr6_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
			    int pkt_len)
{
	int err;

	if (unlikely(dev_recursion_level() > IP_TUNNEL_RECURSION_LIMIT)) {
		net_crit_ratelimited("Dead loop on virtual device %s, fix it urgently!\n",
				     dev->name);
		DEV_STATS_INC(dev, tx_errors);
		kfree_skb_reason(skb, SKB_DROP_REASON_RECURSION_LIMIT);
		return;
	}

	dev_xmit_recursion_inc();

	memset(skb->cb, 0, sizeof(struct inet6_skb_parm));
	skb->protocol = htons(ETH_P_IPV6);

	err = ip6_local_out(dev_net(dev), NULL, skb);
	if (unlikely(net_xmit_eval(err)))
		pkt_len = -1;

	iptunnel_xmit_stats(dev, pkt_len);

	dev_xmit_recursion_dec();
}

static struct dst_entry *sr6_table_lookup(struct net *net, u32 tbl_id,
					  struct flowi6 *fl6)
{
	struct fib6_table *table;
	struct rt6_info *rt;

	table = fib6_get_table(net, tbl_id);
	if (!table)
		return NULL;

	rt = ip6_pol_route(net, table, 0, fl6, NULL, 0);

	return &rt->dst;
}

/* Resolve the route to the first SID, through the configured FIB table or, when
 * none is set, through the VRF context inherited from the device hierarchy.
 * Mirrors seg6_output_dst_lookup() in seg6_iptunnel.c.
 *
 * Always returns a dst with a refcount held. A failure is reported through
 * dst->error, never as NULL.
 */
static struct dst_entry *sr6_dst_lookup(struct net *net,
					struct net_device *dev,
					struct flowi6 *fl6)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct dst_entry *dst;

	if (priv->fib_table) {
		dst = sr6_table_lookup(net, priv->fib_table, fl6);
		if (!dst) {
			dst = &net->ipv6.ip6_blk_hole_entry->dst;
			dst_hold(dst);
		}

		return dst;
	}

	/* Walk the master chain to find the VRF even when sr6 is behind a
	 * bridge; VRF changes are handled by the NETDEV_CHANGEUPPER notifier
	 * which resets the dst_cache.
	 */
	fl6->flowi6_l3mdev = l3mdev_master_upper_ifindex_by_index(net,
								  dev->ifindex);

	return ip6_route_output(net, NULL, fl6);
}

/* Look up the route to the first SID, using the dst_cache when possible.
 *
 * Returns a dst with a refcount held on success, or ERR_PTR on failure.
 * A route pointing back to this device is a routing loop and gives -ELOOP.
 * Every other error is the dst->error of the lookup, such as -ENETUNREACH
 * when there is no route.
 */
static struct dst_entry *sr6_route_lookup(struct net_device *dev,
					  struct sr6_rdst *rdst)
{
	struct net *net = dev_net(dev);
	struct dst_entry *dst;
	struct flowi6 fl6;
	int err;

	local_bh_disable();
	dst = dst_cache_get(&rdst->dst_cache);
	local_bh_enable();

	if (likely(dst))
		return dst;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = rdst->srh->segments[rdst->srh->first_segment];

	dst = sr6_dst_lookup(net, dev, &fl6);
	if (dst->error) {
		err = dst->error;
		goto release_dst;
	}

	if (dst_dev(dst) == dev) {
		err = -ELOOP;
		goto release_dst;
	}

	local_bh_disable();
	dst_cache_set_ip6(&rdst->dst_cache, dst, &fl6.saddr);
	local_bh_enable();

	return dst;

release_dst:
	dst_release(dst);
	return ERR_PTR(err);
}

/*
 * sr6_xmit_one - encapsulate an L2 frame in IPv6+SRH and transmit
 *
 * When the bridge (or local stack) sends a frame through this device, skb->data
 * points to the inner Ethernet header. We look up a route towards the first
 * SID, prepend the outer IPv6+SRH via seg6_do_srh_encap(), and transmit via
 * sr6_tunnel_xmit(). The route lookup result is cached per-cpu, per policy.
 */
static netdev_tx_t sr6_xmit_one(struct sk_buff *skb, struct net_device *dev,
				struct sr6_rdst *rdst)
{
	struct sr6_priv *priv = netdev_priv(dev);
	enum skb_drop_reason reason;
	struct dst_entry *dst;
	int pkt_len, err;

	/* seg6_do_srh_encap reads inner IP headers (flow label, hop limit)
	 * which may not be in the linear area yet. No-op for non-IP frames.
	 */
	reason = pskb_inet_may_pull_reason(skb);
	if (unlikely(reason))
		goto drop;

	dst = sr6_route_lookup(dev, rdst);
	if (unlikely(IS_ERR(dst))) {
		/* A missing FIB table is a configuration error, not a routing
		 * one, so it takes no specific counter: tx_errors alone.
		 */
		if (PTR_ERR(dst) == -ELOOP)
			DEV_STATS_INC(dev, collisions);
		else if (PTR_ERR(dst) == -ENETUNREACH)
			DEV_STATS_INC(dev, tx_carrier_errors);

		DEV_STATS_INC(dev, tx_errors);
		reason = SKB_DROP_REASON_IP_OUTNOROUTES;
		goto free_skb;
	}

	skb_scrub_packet(skb, false);

	skb_dst_set(skb, dst);

	/* inner L2 frame size, before encap adds IPv6+SRH overhead */
	pkt_len = skb->len;

	if (priv->encap_mode == SR6_ENCAP_MODE_REDUCED)
		err = seg6_do_srh_encap_red(skb, rdst->srh, IPPROTO_ETHERNET);
	else
		err = seg6_do_srh_encap(skb, rdst->srh, IPPROTO_ETHERNET);

	if (unlikely(err)) {
		DEV_STATS_INC(dev, tx_errors);
		reason = (err == -ENOMEM) ? SKB_DROP_REASON_NOMEM
					  : SKB_DROP_REASON_NOT_SPECIFIED;
		goto free_skb;
	}

	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	sr6_tunnel_xmit(skb, dev, pkt_len);

	return NETDEV_TX_OK;

drop:
	DEV_STATS_INC(dev, tx_dropped);
free_skb:
	kfree_skb_reason(skb, reason);
	return NETDEV_TX_OK;
}

static netdev_tx_t sr6_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_rdst *rdst = &priv->default_dst;
	struct sr6_fdb *fdb;

	if (unlikely(!pskb_may_pull(skb, ETH_HLEN)))
		goto drop;

	rcu_read_lock();
	fdb = sr6_fdb_lookup(priv, skb->data);
	if (fdb)
		rdst = &fdb->remote;
	if (rdst->srh) {
		sr6_xmit_one(skb, dev, rdst);
		rcu_read_unlock();
		return NETDEV_TX_OK;
	}
	rcu_read_unlock();
drop:
	DEV_STATS_INC(dev, tx_dropped);
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int sr6_dev_init(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);
	int err;

	INIT_LIST_HEAD(&priv->fdb_list);
	err = rhashtable_init(&priv->fdb, &sr6_fdb_rht_params);
	if (err)
		return err;
	err = dst_cache_init(&priv->default_dst.dst_cache, GFP_KERNEL);
	if (err)
		rhashtable_destroy(&priv->fdb);
	return err;
}

/* Free resources allocated in sr6_newlink(). Shared between the error path in
 * sr6_newlink() and the normal teardown in sr6_dev_uninit(), so that new
 * newlink-allocated resources only need to be added in one place.
 */
static void sr6_free_newlink_resources(struct sr6_priv *priv)
{
	kfree(priv->default_dst.srh);
	priv->default_dst.srh = NULL;
}

static void sr6_dev_uninit(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_fdb *fdb, *tmp;

	list_for_each_entry_safe(fdb, tmp, &priv->fdb_list, list)
		sr6_fdb_remove(priv, fdb);
	rhashtable_destroy(&priv->fdb);
	dst_cache_destroy(&priv->default_dst.dst_cache);
	sr6_free_newlink_resources(priv);
}

static const struct net_device_ops sr6_netdev_ops = {
	.ndo_init		= sr6_dev_init,
	.ndo_uninit		= sr6_dev_uninit,
	.ndo_start_xmit		= sr6_xmit,
	.ndo_fdb_add		= sr6_fdb_add,
	.ndo_fdb_del		= sr6_fdb_del,
	.ndo_fdb_dump		= sr6_fdb_dump,
	.ndo_fdb_get		= sr6_fdb_get,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

static void sr6_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &sr6_netdev_ops;
	dev->needs_free_netdev = true;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_DSTATS;
	dev->max_mtu = ETH_MAX_MTU;
	dev->needed_headroom = LL_MAX_HEADER + sizeof(struct ipv6hdr) +
			       SR6_SRH_HEADROOM_EST;

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	dev->lltx = true;

	/* The device carries an SRv6 tunnel bound to a routing context; moving
	 * it to another netns would break that context and the dst_cache.
	 */
	dev->netns_immutable = true;

	eth_hw_addr_random(dev);
}

static const struct nla_policy sr6_policy[IFLA_SR6_MAX + 1] = {
	[IFLA_SR6_SRH]		= { .type = NLA_BINARY },
	[IFLA_SR6_FIB_TABLE]	= { .type = NLA_U32 },
	[IFLA_SR6_ENCAP_MODE]	= NLA_POLICY_MAX(NLA_U8, SR6_ENCAP_MODE_MAX),
};

static int sr6_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (!data || !data[IFLA_SR6_ENCAP_MODE]) {
		NL_SET_ERR_MSG(extack, "Encapsulation mode is required");
		return -EINVAL;
	}

	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (data[IFLA_SR6_SRH])
		return sr6_srh_validate(data[IFLA_SR6_SRH], extack);

	return 0;
}

/* Set dev->mtu and dev->max_mtu from the encapsulation overhead, made of the
 * outer IPv6 header, the SRH and the inner ETH_HLEN, since the whole Ethernet
 * frame is carried.
 *
 * A user-supplied MTU is refused when the encapsulated frame would not fit
 * IP_MAX_MTU. The core checked it already, but before the SRH was known.
 * Refused and not lowered, so the device comes up with what was asked.
 */
static int sr6_set_mtu(struct net_device *dev, struct nlattr *tb[], int srhlen,
		       struct netlink_ext_ack *extack)
{
	int overhead = sizeof(struct ipv6hdr) + srhlen + ETH_HLEN;
	int max_mtu = IP_MAX_MTU - overhead;
	int default_mtu;

	dev->max_mtu = max_mtu;

	if (!tb[IFLA_MTU]) {
		/* make room in the Ethernet default. Signed, because a large
		 * SRH drives it negative and max() must pick ETH_MIN_MTU.
		 */
		default_mtu = ETH_DATA_LEN - overhead;
		dev->mtu = max(default_mtu, ETH_MIN_MTU);
	} else if (dev->mtu > max_mtu) {
		NL_SET_ERR_MSG(extack, "MTU exceeds the encapsulation limit");
		return -EINVAL;
	}

	return 0;
}

static int sr6_newlink(struct net_device *dev,
			struct rtnl_newlink_params *params,
			struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct nlattr **data = params->data;
	int srhlen, err;

	/* already validated by the nla policy */
	priv->encap_mode = nla_get_u8(data[IFLA_SR6_ENCAP_MODE]);

	/* Without a fallback, start with the overhead of a single SID.
	 * FDB policies raise the headroom hint and lower max_mtu as needed.
	 */
	srhlen = priv->encap_mode == SR6_ENCAP_MODE_REDUCED ? 0 :
		 sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr);
	if (data[IFLA_SR6_SRH]) {
		/* Both modes take a full, validated SID list from userspace. */
		priv->default_dst.srh = nla_memdup(data[IFLA_SR6_SRH], GFP_KERNEL);
		if (!priv->default_dst.srh)
			return -ENOMEM;
		srhlen = sr6_encap_srhlen(priv->default_dst.srh, priv->encap_mode);
	}

	if (data[IFLA_SR6_FIB_TABLE]) {
		priv->fib_table = nla_get_u32(data[IFLA_SR6_FIB_TABLE]);
		if (!priv->fib_table) {
			NL_SET_ERR_MSG(extack, "Invalid FIB table ID");
			sr6_free_newlink_resources(priv);
			return -EINVAL;
		}
	}

	dev->needed_headroom = LL_MAX_HEADER + sizeof(struct ipv6hdr) + srhlen;

	err = sr6_set_mtu(dev, params->tb, srhlen, extack);
	if (err) {
		sr6_free_newlink_resources(priv);
		return err;
	}

	err = register_netdevice(dev);
	if (err) {
		sr6_free_newlink_resources(priv);
		return err;
	}

	return 0;
}

static void sr6_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}

static size_t sr6_get_size(const struct net_device *dev)
{
	const struct sr6_priv *priv = netdev_priv(dev);
	size_t size = priv->default_dst.srh ?
		nla_total_size(ipv6_optlen(priv->default_dst.srh)) : 0;

	return size			/* IFLA_SR6_SRH */
	       + nla_total_size(4)	/* IFLA_SR6_FIB_TABLE */
	       + nla_total_size(1);	/* IFLA_SR6_ENCAP_MODE */
}

static int sr6_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct sr6_priv *priv = netdev_priv(dev);
	struct ipv6_sr_hdr *srh = priv->default_dst.srh;

	if (srh && nla_put(skb, IFLA_SR6_SRH, ipv6_optlen(srh), srh))
		return -EMSGSIZE;

	if (priv->fib_table &&
	    nla_put_u32(skb, IFLA_SR6_FIB_TABLE, priv->fib_table))
		return -EMSGSIZE;

	if (nla_put_u8(skb, IFLA_SR6_ENCAP_MODE, priv->encap_mode))
		return -EMSGSIZE;

	return 0;
}

static struct rtnl_link_ops sr6_link_ops __read_mostly = {
	.kind		= "sr6",
	.maxtype	= IFLA_SR6_MAX,
	.policy		= sr6_policy,
	.priv_size	= sizeof(struct sr6_priv),
	.setup		= sr6_setup,
	.validate	= sr6_validate,
	.newlink	= sr6_newlink,
	.dellink	= sr6_dellink,
	.get_size	= sr6_get_size,
	.fill_info	= sr6_fill_info,
};

static int sr6_reset_dst_cache(struct net_device *dev,
			       struct netdev_nested_priv *priv)
{
	struct sr6_priv *sp;
	struct sr6_fdb *fdb;

	if (!netif_is_sr6(dev))
		return 0;

	sp = netdev_priv(dev);
	dst_cache_reset(&sp->default_dst.dst_cache);
	rcu_read_lock();
	list_for_each_entry_rcu(fdb, &sp->fdb_list, list)
		dst_cache_reset(&fdb->remote.dst_cache);
	rcu_read_unlock();

	return 0;
}

/* Reset the dst_cache of sr6 devices whose l3mdev context may have changed. */
static int sr6_netdev_event(struct notifier_block *nb, unsigned long event,
			    void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_nested_priv priv = { };

	if (event != NETDEV_CHANGEUPPER)
		return NOTIFY_DONE;

	/* sr6_route_lookup() resolves the l3mdev by walking the master chain,
	 * so a change anywhere along it can affect the sr6 devices below.
	 * Reset the device of the event and all its lower devices, no matter
	 * what the new upper is: a spurious reset costs one route lookup.
	 */
	sr6_reset_dst_cache(dev, NULL);
	netdev_walk_all_lower_dev(dev, sr6_reset_dst_cache, &priv);

	return NOTIFY_DONE;
}

static struct notifier_block sr6_notifier_block __read_mostly = {
	.notifier_call = sr6_netdev_event,
};

static int __init sr6_init(void)
{
	int err;

	err = register_netdevice_notifier(&sr6_notifier_block);
	if (err)
		return err;

	err = rtnl_link_register(&sr6_link_ops);
	if (err) {
		unregister_netdevice_notifier(&sr6_notifier_block);
		return err;
	}

	return 0;
}

static void __exit sr6_exit(void)
{
	rtnl_link_unregister(&sr6_link_ops);
	unregister_netdevice_notifier(&sr6_notifier_block);
	/* FDB callbacks execute module code and may outlive the netdevice. */
	rcu_barrier();
}

module_init(sr6_init);
module_exit(sr6_exit);

MODULE_AUTHOR("Andrea Mayer <andrea.mayer@uniroma2.it>");
MODULE_AUTHOR("Stefano Salsano <stefano.salsano@uniroma2.it>");
MODULE_DESCRIPTION("SRv6 L2 tunnel device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("sr6");
