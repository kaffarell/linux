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
 *  IPPROTO_ETHERNET (143). The route to the first SID is looked up in the
 *  configured FIB table or, without one, with ip6_route_output(), and it is
 *  kept in a dst_cache.
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

/* Initial estimate for SRH size before newlink provides the actual value.
 * 256 bytes accommodates up to 15 SIDs.
 */
#define SR6_SRH_HEADROOM_EST	256

struct sr6_config {
	struct ipv6_sr_hdr	*srh;
	/* replaced with the configuration, so it never holds a stale route */
	struct dst_cache	dst_cache;
	u32			fib_table;
	u8			encap_mode;
	struct rcu_head		rcu;
};

struct sr6_priv {
	struct sr6_config __rcu	*config;
};

/* SRH length for the given encapsulation mode. The full mode keeps the
 * configured SRH. The reduced one pushes no SRH for a single SID with no other
 * info. Otherwise it leaves out the first SID, unless it is the only one.
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

static struct sr6_config *sr6_config_alloc(void)
{
	struct sr6_config *cfg;
	int err;

	cfg = kzalloc_obj(*cfg);
	if (!cfg)
		return ERR_PTR(-ENOMEM);

	err = dst_cache_init(&cfg->dst_cache, GFP_KERNEL);
	if (err) {
		kfree(cfg);
		return ERR_PTR(err);
	}

	return cfg;
}

static void sr6_config_free(struct sr6_config *cfg)
{
	if (cfg) {
		dst_cache_destroy(&cfg->dst_cache);
		kfree(cfg->srh);
		kfree(cfg);
	}
}

static void sr6_config_free_rcu(struct rcu_head *head)
{
	struct sr6_config *cfg = container_of(head, struct sr6_config, rcu);

	sr6_config_free(cfg);
}

static struct sr6_config *sr6_config_rtnl(const struct net_device *dev)
{
	const struct sr6_priv *priv = netdev_priv(dev);

	return rtnl_dereference(priv->config);
}

static struct sr6_config *sr6_config_rcu(const struct net_device *dev)
{
	const struct sr6_priv *priv = netdev_priv(dev);

	return rcu_dereference(priv->config);
}

/* Release the configuration of a device that is going away. Reached through
 * priv_destructor and, explicitly, when the registration fails, so it has to
 * be safe against running twice.
 */
static void sr6_free_dev(struct net_device *dev)
{
	struct sr6_config *cfg;
	struct sr6_priv *priv;

	priv = netdev_priv(dev);

	/* RTNL is held when the registration fails and is not held when the
	 * device is destroyed, so no single lock can be asserted here. On
	 * either path priv->config has no reader left.
	 */
	cfg = rcu_dereference_protected(priv->config, 1);

	sr6_config_free(cfg);
	RCU_INIT_POINTER(priv->config, NULL);
}

/* Transmit an encapsulated frame and account for it.
 *
 * The payload length comes from the caller, which saves skb->len before the
 * encapsulation. sr6 carries Ethernet frames and, like the L2ENCAP mode in
 * seg6_iptunnel.c, has no GSO type to hand iptunnel_handle_offloads(), so the
 * inner network offset that ip6tunnel_xmit() derives the length from is never
 * set here.
 *
 * sr6_route_lookup() refuses a route through this device. A loop that passes
 * through another device is not caught there, and the recursion limit stops
 * it. See IP_TUNNEL_RECURSION_LIMIT.
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
					const struct sr6_config *cfg,
					struct flowi6 *fl6)
{
	struct dst_entry *dst;

	if (cfg->fib_table) {
		dst = sr6_table_lookup(net, cfg->fib_table, fl6);
		if (!dst) {
			dst = &net->ipv6.ip6_blk_hole_entry->dst;
			dst_hold(dst);
		}

		return dst;
	}

	/* Walk the master chain to find the VRF even when sr6 is behind a
	 * bridge. VRF changes are handled by the NETDEV_CHANGEUPPER notifier
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
					  struct sr6_config *cfg)
{
	struct dst_entry *dst;
	struct flowi6 fl6;
	struct net *net;
	int err;

	local_bh_disable();
	dst = dst_cache_get(&cfg->dst_cache);
	local_bh_enable();

	if (likely(dst))
		return dst;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = cfg->srh->segments[cfg->srh->first_segment];

	net = dev_net(dev);
	dst = sr6_dst_lookup(net, dev, cfg, &fl6);
	if (dst->error) {
		err = dst->error;
		goto release_dst;
	}

	if (dst_dev(dst) == dev) {
		err = -ELOOP;
		goto release_dst;
	}

	local_bh_disable();
	dst_cache_set_ip6(&cfg->dst_cache, dst, &fl6.saddr);
	local_bh_enable();

	return dst;

release_dst:
	dst_release(dst);
	return ERR_PTR(err);
}

/* Encapsulate an L2 frame in IPv6+SRH and transmit.
 *
 * When the bridge (or local stack) sends a frame through this device,
 * skb->data points to its Ethernet header.
 */
static netdev_tx_t sr6_xmit(struct sk_buff *skb, struct net_device *dev)
{
	enum skb_drop_reason reason;
	struct sr6_config *cfg;
	struct dst_entry *dst;
	int pkt_len;
	int err;

	/* seg6_do_srh_encap() and seg6_do_srh_encap_red() read the traffic
	 * class, the flow label and the hop limit of an inner IPv6 header,
	 * which may not be in the linear area yet.
	 */
	reason = pskb_inet_may_pull_reason(skb);
	if (unlikely(reason))
		goto drop;

	rcu_read_lock();

	cfg = sr6_config_rcu(dev);

	dst = sr6_route_lookup(dev, cfg);
	if (unlikely(IS_ERR(dst))) {
		rcu_read_unlock();

		/* -ELOOP and -ENETUNREACH have a dedicated counter. Every other
		 * error, such as a missing FIB table, takes tx_errors alone.
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

	if (cfg->encap_mode == SR6_ENCAP_MODE_REDUCED)
		err = seg6_do_srh_encap_red(skb, cfg->srh, IPPROTO_ETHERNET);
	else
		err = seg6_do_srh_encap(skb, cfg->srh, IPPROTO_ETHERNET);

	rcu_read_unlock();

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

static const struct net_device_ops sr6_netdev_ops = {
	.ndo_start_xmit		= sr6_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

static void sr6_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &sr6_netdev_ops;
	dev->needs_free_netdev = true;
	dev->priv_destructor = sr6_free_dev;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_DSTATS;
	dev->max_mtu = ETH_MAX_MTU;
	dev->needed_headroom = LL_MAX_HEADER + sizeof(struct ipv6hdr) +
			       SR6_SRH_HEADROOM_EST;

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	dev->lltx = true;

	/* The device carries an SRv6 tunnel bound to a routing context. Moving
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

/* runs on a change as well as on a creation */
static int sr6_validate(struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_ADDRESS],
					    "Provided link layer address is not Ethernet");
			return -EINVAL;
		}

		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_ADDRESS],
					    "Provided Ethernet address is not unicast");
			return -EADDRNOTAVAIL;
		}
	}

	if (!data || !data[IFLA_SR6_SRH]) {
		NL_SET_ERR_MSG(extack, "SRH with segment list is required");
		return -EINVAL;
	}

	/* The mode and the FIB table are checked by sr6_nl2config(), which
	 * receives old_cfg, NULL on a creation, and so can require the mode on
	 * a creation and accept a new one afterwards.
	 */
	return 0;
}

/* Whatever the mode, userspace configures the full SID list and never a
 * reduced SRH.
 */
static int sr6_nl2srh(struct nlattr *data[], struct sr6_config *new_cfg,
		      struct netlink_ext_ack *extack)
{
	struct ipv6_sr_hdr *srh;
	int len;

	srh = nla_data(data[IFLA_SR6_SRH]);
	len = nla_len(data[IFLA_SR6_SRH]);

	if (len < sizeof(*srh) + sizeof(struct in6_addr)) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_SR6_SRH],
				    "SRH too short");
		return -EINVAL;
	}

	if (!seg6_validate_srh(srh, len, false)) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_SR6_SRH], "Invalid SRH");
		return -EINVAL;
	}

	new_cfg->srh = kmemdup(srh, len, GFP_KERNEL);
	if (!new_cfg->srh)
		return -ENOMEM;

	return 0;
}

static int sr6_nl2encap_mode(struct nlattr *data[], struct sr6_config *new_cfg,
			     const struct sr6_config *old_cfg,
			     struct netlink_ext_ack *extack)
{
	if (!data[IFLA_SR6_ENCAP_MODE]) {
		if (!old_cfg) {
			NL_SET_ERR_MSG(extack,
				       "Encapsulation mode is required");
			return -EINVAL;
		}

		new_cfg->encap_mode = old_cfg->encap_mode;

		return 0;
	}

	/* already validated by the nla policy */
	new_cfg->encap_mode = nla_get_u8(data[IFLA_SR6_ENCAP_MODE]);

	return 0;
}

static int sr6_nl2fib_table(struct nlattr *data[], struct sr6_config *new_cfg,
			    const struct sr6_config *old_cfg,
			    struct netlink_ext_ack *extack)
{
	u32 fib_table;

	if (!data[IFLA_SR6_FIB_TABLE]) {
		if (old_cfg)
			new_cfg->fib_table = old_cfg->fib_table;

		return 0;
	}

	fib_table = nla_get_u32(data[IFLA_SR6_FIB_TABLE]);
	if (old_cfg && fib_table != old_cfg->fib_table) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_SR6_FIB_TABLE],
				    "Cannot change the FIB table");
		return -EOPNOTSUPP;
	}

	if (!old_cfg && !fib_table) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_SR6_FIB_TABLE],
				    "Invalid FIB table ID");
		return -EINVAL;
	}

	new_cfg->fib_table = fib_table;

	return 0;
}

static int sr6_nl2config(struct nlattr *data[],
			 struct sr6_config *new_cfg,
			 const struct sr6_config *old_cfg,
			 struct netlink_ext_ack *extack)
{
	int err;

	err = sr6_nl2encap_mode(data, new_cfg, old_cfg, extack);
	if (err)
		return err;

	err = sr6_nl2fib_table(data, new_cfg, old_cfg, extack);
	if (err)
		return err;

	return sr6_nl2srh(data, new_cfg, extack);
}

static int sr6_encap_overhead(int srhlen)
{
	return sizeof(struct ipv6hdr) + srhlen + ETH_HLEN;
}

static int sr6_max_mtu(int srhlen)
{
	return IP_MAX_MTU - sr6_encap_overhead(srhlen);
}

static int sr6_default_mtu(int srhlen)
{
	/* Signed, because a long SRH drives the difference negative and max()
	 * must pick ETH_MIN_MTU.
	 */
	return max(ETH_DATA_LEN - sr6_encap_overhead(srhlen), ETH_MIN_MTU);
}

/* A user-supplied MTU is refused when the encapsulated frame would not fit
 * IP_MAX_MTU. The core checked it already, but before the SRH was known.
 * Refused and not lowered: the device comes up with what was asked.
 */
static int sr6_set_mtu_newlink(struct net_device *dev, struct nlattr *tb[],
			       int srhlen, struct netlink_ext_ack *extack)
{
	int max_mtu = sr6_max_mtu(srhlen);

	dev->max_mtu = max_mtu;

	if (!tb[IFLA_MTU]) {
		dev->mtu = sr6_default_mtu(srhlen);
		return 0;
	}

	/* rtnl_create_link() has already written dev->mtu from the attribute,
	 * so the value asked for is the one to test.
	 */
	if (dev->mtu > max_mtu) {
		NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_MTU],
				    "MTU exceeds the encapsulation limit");
		return -EINVAL;
	}

	return 0;
}

/* The overhead depends on the SRH that the new configuration pushes, and both
 * the segment list and the mode change it. The MTU is computed again for it.
 * An MTU given in the same request is used instead, and a user who wants to
 * keep one has to pass it again.
 */
static int sr6_set_mtu_changelink(struct net_device *dev, struct nlattr *tb[],
				  int new_srhlen,
				  struct netlink_ext_ack *extack)
{
	int new_max_mtu = sr6_max_mtu(new_srhlen);
	int old_max_mtu = dev->max_mtu;
	int new_mtu;
	int err;

	/* dev->max_mtu has to hold the value for the new configuration before
	 * netif_set_mtu() below, which is checked against it. A shorter SRH
	 * gives a larger MTU, and the previous dev->max_mtu would refuse it.
	 */
	dev->max_mtu = new_max_mtu;

	new_mtu = sr6_default_mtu(new_srhlen);

	if (tb[IFLA_MTU]) {
		u32 mtu = nla_get_u32(tb[IFLA_MTU]);

		/* netif_set_mtu() below applies it before the configuration is
		 * published, and do_setlink() then finds it in place. The range
		 * is tested here because netif_set_mtu() reports no reason, and
		 * it does not test a value equal to the current MTU.
		 */
		if (mtu > new_max_mtu) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_MTU],
					    "MTU exceeds the encapsulation limit");
			goto refuse;
		}

		/* rtnl_create_link() checks the lower bound at creation, but
		 * nothing has checked this one yet.
		 */
		if (mtu < dev->min_mtu) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_MTU],
					    "MTU below the device minimum");
			goto refuse;
		}

		new_mtu = mtu;
	}

	err = netif_set_mtu(dev, new_mtu);
	if (err) {
		dev->max_mtu = old_max_mtu;
		return err;
	}

	return 0;

refuse:
	dev->max_mtu = old_max_mtu;
	return -EINVAL;
}

static int sr6_config2dev(struct net_device *dev, struct nlattr *tb[],
			  const struct sr6_config *new_cfg,
			  const struct sr6_config *old_cfg,
			  struct netlink_ext_ack *extack)
{
	int new_srhlen = sr6_encap_srhlen(new_cfg->srh, new_cfg->encap_mode);
	int err;

	if (old_cfg)
		err = sr6_set_mtu_changelink(dev, tb, new_srhlen, extack);
	else
		err = sr6_set_mtu_newlink(dev, tb, new_srhlen, extack);

	if (err)
		return err;

	dev->needed_headroom = LL_MAX_HEADER + sizeof(struct ipv6hdr) +
			       new_srhlen;

	return 0;
}

/* store the new configuration on the device and release the previous one */
static int sr6_config_apply(struct net_device *dev, struct nlattr *tb[],
			    struct sr6_config *new_cfg,
			    struct sr6_config *old_cfg,
			    struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv;
	int err;

	err = sr6_config2dev(dev, tb, new_cfg, old_cfg, extack);
	if (err)
		return err;

	priv = netdev_priv(dev);
	rcu_assign_pointer(priv->config, new_cfg);

	if (old_cfg)
		call_rcu_hurry(&old_cfg->rcu, sr6_config_free_rcu);

	return 0;
}

static int sr6_configure(struct net_device *dev, struct nlattr *tb[],
			 struct nlattr *data[], struct sr6_config *old_cfg,
			 struct netlink_ext_ack *extack)
{
	struct sr6_config *cfg;
	int err;

	cfg = sr6_config_alloc();
	if (IS_ERR(cfg))
		return PTR_ERR(cfg);

	err = sr6_nl2config(data, cfg, old_cfg, extack);
	if (err)
		goto free_cfg;

	err = sr6_config_apply(dev, tb, cfg, old_cfg, extack);
	if (err)
		goto free_cfg;

	return 0;

free_cfg:
	sr6_config_free(cfg);
	return err;
}

static int sr6_newlink(struct net_device *dev,
		       struct rtnl_newlink_params *params,
		       struct netlink_ext_ack *extack)
{
	int err;

	err = sr6_configure(dev, params->tb, params->data, NULL, extack);
	if (err)
		return err;

	err = register_netdevice(dev);
	if (err)
		sr6_free_dev(dev);

	return err;
}

static int sr6_changelink(struct net_device *dev, struct nlattr *tb[],
			  struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	struct sr6_config *old_cfg = sr6_config_rtnl(dev);

	return sr6_configure(dev, tb, data, old_cfg, extack);
}

static void sr6_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}

static size_t sr6_get_size(const struct net_device *dev)
{
	const struct sr6_config *cfg;
	size_t srh_size = 0;
	int srhlen;

	rcu_read_lock();

	cfg = sr6_config_rcu(dev);
	if (cfg) {
		srhlen = ipv6_optlen(cfg->srh);
		srh_size = nla_total_size(srhlen);
	}

	rcu_read_unlock();

	return srh_size			/* IFLA_SR6_SRH */
	       + nla_total_size(4)	/* IFLA_SR6_FIB_TABLE */
	       + nla_total_size(1);	/* IFLA_SR6_ENCAP_MODE */
}

static int sr6_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct sr6_config *cfg;
	int err = 0;
	int srhlen;

	rcu_read_lock();

	cfg = sr6_config_rcu(dev);
	if (!cfg) {
		err = -ENODEV;
		goto out;
	}

	srhlen = ipv6_optlen(cfg->srh);
	if (nla_put(skb, IFLA_SR6_SRH, srhlen, cfg->srh))
		goto nla_put_failure;

	if (cfg->fib_table &&
	    nla_put_u32(skb, IFLA_SR6_FIB_TABLE, cfg->fib_table))
		goto nla_put_failure;

	if (nla_put_u8(skb, IFLA_SR6_ENCAP_MODE, cfg->encap_mode))
		goto nla_put_failure;

out:
	rcu_read_unlock();

	return err;

nla_put_failure:
	err = -EMSGSIZE;
	goto out;
}

static struct rtnl_link_ops sr6_link_ops __read_mostly = {
	.kind		= "sr6",
	.maxtype	= IFLA_SR6_MAX,
	.policy		= sr6_policy,
	.priv_size	= sizeof(struct sr6_priv),
	.setup		= sr6_setup,
	.validate	= sr6_validate,
	.newlink	= sr6_newlink,
	.changelink	= sr6_changelink,
	.dellink	= sr6_dellink,
	.get_size	= sr6_get_size,
	.fill_info	= sr6_fill_info,
};

static int sr6_reset_dst_cache(struct net_device *dev,
			       struct netdev_nested_priv *priv)
{
	struct sr6_config *cfg;

	if (!netif_is_sr6(dev))
		return 0;

	cfg = sr6_config_rtnl(dev);
	dst_cache_reset(&cfg->dst_cache);

	return 0;
}

/* reset the dst_cache of sr6 devices whose l3mdev context may have changed */
static int sr6_netdev_event(struct notifier_block *nb, unsigned long event,
			    void *ptr)
{
	struct netdev_nested_priv priv = { };
	struct net_device *dev;

	if (event != NETDEV_CHANGEUPPER)
		return NOTIFY_DONE;

	dev = netdev_notifier_info_to_dev(ptr);

	/* sr6_dst_lookup() resolves the l3mdev by walking the master chain,
	 * so a change anywhere along it can affect the sr6 devices below.
	 * Reset the device of the event and all its lower devices, no matter
	 * what the new upper is. A reset that was not needed makes the next
	 * transmit on each CPU look up the route again.
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

	/* Wait for the sr6_config_free_rcu() callbacks a changelink may have
	 * left queued: their code goes away with the module, and a grace
	 * period does not wait for a callback to run.
	 */
	rcu_barrier();
}

module_init(sr6_init);
module_exit(sr6_exit);

MODULE_AUTHOR("Andrea Mayer <andrea.mayer@uniroma2.it>");
MODULE_AUTHOR("Stefano Salsano <stefano.salsano@uniroma2.it>");
MODULE_DESCRIPTION("SRv6 L2 tunnel device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("sr6");
