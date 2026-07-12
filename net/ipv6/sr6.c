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

struct sr6_priv {
	struct ipv6_sr_hdr	*srh;
	struct dst_cache	dst_cache;
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
static struct dst_entry *sr6_route_lookup(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct dst_entry *dst;
	struct flowi6 fl6;
	int err;

	local_bh_disable();
	dst = dst_cache_get(&priv->dst_cache);
	local_bh_enable();

	if (likely(dst))
		return dst;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = priv->srh->segments[priv->srh->first_segment];

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
	dst_cache_set_ip6(&priv->dst_cache, dst, &fl6.saddr);
	local_bh_enable();

	return dst;

release_dst:
	dst_release(dst);
	return ERR_PTR(err);
}

/*
 * sr6_xmit - encapsulate an L2 frame in IPv6+SRH and transmit
 *
 * When the bridge (or local stack) sends a frame through this device, skb->data
 * points to the inner Ethernet header. We look up a route towards the first
 * SID, prepend the outer IPv6+SRH via seg6_do_srh_encap(), and transmit via
 * sr6_tunnel_xmit(). The route lookup result is cached per-cpu.
 */
static netdev_tx_t sr6_xmit(struct sk_buff *skb, struct net_device *dev)
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

	dst = sr6_route_lookup(dev);
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
		err = seg6_do_srh_encap_red(skb, priv->srh, IPPROTO_ETHERNET);
	else
		err = seg6_do_srh_encap(skb, priv->srh, IPPROTO_ETHERNET);

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

static int sr6_dev_init(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);

	return dst_cache_init(&priv->dst_cache, GFP_KERNEL);
}

/* Free resources allocated in sr6_newlink(). Shared between the error path in
 * sr6_newlink() and the normal teardown in sr6_dev_uninit(), so that new
 * newlink-allocated resources only need to be added in one place.
 */
static void sr6_free_newlink_resources(struct sr6_priv *priv)
{
	kfree(priv->srh);
	priv->srh = NULL;
}

static void sr6_dev_uninit(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);

	dst_cache_destroy(&priv->dst_cache);
	sr6_free_newlink_resources(priv);
}

static const struct net_device_ops sr6_netdev_ops = {
	.ndo_init		= sr6_dev_init,
	.ndo_uninit		= sr6_dev_uninit,
	.ndo_start_xmit		= sr6_xmit,
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
	if (!data || !data[IFLA_SR6_SRH]) {
		NL_SET_ERR_MSG(extack, "SRH with segment list is required");
		return -EINVAL;
	}

	if (!data[IFLA_SR6_ENCAP_MODE]) {
		NL_SET_ERR_MSG(extack, "Encapsulation mode is required");
		return -EINVAL;
	}

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
	struct ipv6_sr_hdr *srh;
	int srhlen;
	int err;
	int len;

	srh = nla_data(data[IFLA_SR6_SRH]);
	len = nla_len(data[IFLA_SR6_SRH]);

	if (len < sizeof(*srh) + sizeof(struct in6_addr)) {
		NL_SET_ERR_MSG(extack, "SRH too short");
		return -EINVAL;
	}

	/* Whatever the mode, userspace configures the full SID list and never
	 * a reduced SRH.
	 */
	if (!seg6_validate_srh(srh, len, false)) {
		NL_SET_ERR_MSG(extack, "Invalid SRH");
		return -EINVAL;
	}

	priv->srh = kmemdup(srh, len, GFP_KERNEL);
	if (!priv->srh)
		return -ENOMEM;

	/* already validated by the nla policy */
	priv->encap_mode = nla_get_u8(data[IFLA_SR6_ENCAP_MODE]);

	srhlen = sr6_encap_srhlen(srh, priv->encap_mode);

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
	int srhlen = ipv6_optlen(priv->srh);

	return nla_total_size(srhlen)	/* IFLA_SR6_SRH */
	       + nla_total_size(4)	/* IFLA_SR6_FIB_TABLE */
	       + nla_total_size(1);	/* IFLA_SR6_ENCAP_MODE */
}

static int sr6_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct sr6_priv *priv = netdev_priv(dev);
	int srhlen = ipv6_optlen(priv->srh);

	if (nla_put(skb, IFLA_SR6_SRH, srhlen, priv->srh))
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

	if (!netif_is_sr6(dev))
		return 0;

	sp = netdev_priv(dev);
	dst_cache_reset(&sp->dst_cache);

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
}

module_init(sr6_init);
module_exit(sr6_exit);

MODULE_AUTHOR("Andrea Mayer <andrea.mayer@uniroma2.it>");
MODULE_AUTHOR("Stefano Salsano <stefano.salsano@uniroma2.it>");
MODULE_DESCRIPTION("SRv6 L2 tunnel device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("sr6");
