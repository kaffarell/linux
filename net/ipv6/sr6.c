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
 *  Each remote PE is described by an SRv6 policy held in the device FDB. The
 *  FDB maps a destination MAC to one remote, and the all-zeros MAC to the
 *  remote that receives every other frame. ip link configures the all-zeros
 *  entry through the same code as the FDB interface.
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
#include <net/rtnetlink.h>
#include <net/seg6.h>
#include <net/sr6.h>
#include <linux/seg6.h>
#include <linux/if_link.h>
#include <linux/neighbour.h>

/* Initial estimate for SRH size before the first policy is installed.
 * 256 bytes accommodates up to 15 SIDs.
 */
#define SR6_SRH_HEADROOM_EST	256

/* An SRv6 policy toward one remote PE. Immutable once published: an update
 * replaces the whole remote, so a reader never pairs a cached route with a
 * different SID list, mode or table.
 */
struct sr6_remote {
	struct list_head	list;
	struct ipv6_sr_hdr	*srh;
	struct dst_cache	dst_cache;
	u32			fib_table;
	u8			encap_mode;
	struct rcu_head		rcu;
};

/* An FDB entry and its remote. A list, so that an entry can later hold
 * more than one.
 */
struct sr6_fdb {
	struct rhash_head	rhnode;
	struct hlist_node	node;
	struct list_head	remotes;
	u8			addr[ETH_ALEN];
	u16			state;	         /* see ndm_state */
	struct rcu_head		rcu;
};

/* RTNL serializes writers, transmit and dumps read under RCU. The hash table
 * serves lookups, the list a stable order for dumps and walks over every entry.
 */
struct sr6_priv {
	struct rhashtable	fdb_hash;
	struct hlist_head	fdb_list;
	bool			fdb_ready;
};

static const struct rhashtable_params sr6_fdb_rht_params = {
	.head_offset		= offsetof(struct sr6_fdb, rhnode),
	.key_offset		= offsetof(struct sr6_fdb, addr),
	.key_len		= ETH_ALEN,
	.automatic_shrinking	= true,
};

static const u8 sr6_zero_mac[ETH_ALEN];

/* The fields of a request that describe a remote. srh points into the
 * request and is copied only when a remote is built from it.
 */
struct sr6_policy {
	const struct ipv6_sr_hdr *srh;
	u32			fib_table;
	u8			encap_mode;
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

/* Called under RCU or RTNL, which keeps the entry alive. */
static struct sr6_fdb *sr6_fdb_find(struct sr6_priv *priv, const u8 *addr)
{
	return rhashtable_lookup_fast(&priv->fdb_hash, addr, sr6_fdb_rht_params);
}

static void sr6_remote_free(struct sr6_remote *rd)
{
	dst_cache_destroy(&rd->dst_cache);
	kfree(rd->srh);
	kfree(rd);
}

static void sr6_remote_free_rcu(struct rcu_head *head)
{
	sr6_remote_free(container_of(head, struct sr6_remote, rcu));
}

static struct sr6_remote *sr6_remote_create(const struct sr6_policy *pol)
{
	struct sr6_remote *rd;

	rd = kzalloc_obj(*rd);
	if (!rd)
		return NULL;

	rd->srh = kmemdup(pol->srh, ipv6_optlen(pol->srh), GFP_KERNEL);
	if (!rd->srh)
		goto free;

	if (dst_cache_init(&rd->dst_cache, GFP_KERNEL))
		goto free;

	rd->fib_table = pol->fib_table;
	rd->encap_mode = pol->encap_mode;

	return rd;

free:
	kfree(rd->srh);
	kfree(rd);
	return NULL;
}

/* A remote is identified by its SRH and its table, not by its mode. */
static bool sr6_remote_match(const struct sr6_remote *rd,
			     const struct sr6_policy *sel)
{
	int len = ipv6_optlen(rd->srh);

	return rd->fib_table == sel->fib_table &&
	       len == ipv6_optlen(sel->srh) &&
	       !memcmp(rd->srh, sel->srh, len);
}

static struct sr6_remote *sr6_fdb_first(struct sr6_fdb *fdb)
{
	return list_first_or_null_rcu(&fdb->remotes, struct sr6_remote, list);
}

static size_t sr6_fdb_nlmsg_size(const struct sr6_remote *rd)
{
	return NLMSG_ALIGN(sizeof(struct ndmsg))
	       + nla_total_size(ETH_ALEN)		/* NDA_LLADDR */
	       + nla_total_size(0)			/* NDA_SR6 */
	       + nla_total_size(ipv6_optlen(rd->srh))	/* NDA_SR6_SRH */
	       + nla_total_size(1)			/* NDA_SR6_MODE */
	       + nla_total_size(4);			/* NDA_SR6_TABLE */
}

static int sr6_fdb_info(struct sk_buff *skb, struct net_device *dev,
			const struct sr6_fdb *fdb,
			const struct sr6_remote *rd, u32 portid, u32 seq,
			int type, unsigned int flags)
{
	struct nlmsghdr *nlh;
	struct nlattr *nest;
	struct ndmsg *ndm;

	nlh = nlmsg_put(skb, portid, seq, type, sizeof(*ndm), flags);
	if (!nlh)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	memset(ndm, 0, sizeof(*ndm));
	ndm->ndm_family = AF_BRIDGE;
	ndm->ndm_ifindex = dev->ifindex;
	ndm->ndm_state = READ_ONCE(fdb->state);
	ndm->ndm_flags = NTF_SELF;
	ndm->ndm_type = RTN_UNICAST;

	if (nla_put(skb, NDA_LLADDR, ETH_ALEN, fdb->addr))
		goto cancel;

	nest = nla_nest_start(skb, NDA_SR6);
	if (!nest)
		goto cancel;

	if (nla_put(skb, NDA_SR6_SRH, ipv6_optlen(rd->srh), rd->srh) ||
	    nla_put_u8(skb, NDA_SR6_MODE, rd->encap_mode) ||
	    (rd->fib_table && nla_put_u32(skb, NDA_SR6_TABLE, rd->fib_table)))
		goto cancel;

	nla_nest_end(skb, nest);
	nlmsg_end(skb, nlh);
	return 0;

cancel:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static void sr6_fdb_notify(struct net_device *dev, const struct sr6_fdb *fdb,
			   const struct sr6_remote *rd, int type)
{
	struct net *net = dev_net(dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;

	/* A device being created is announced by the core, with the policy it
	 * was created with in IFLA_SR6_*. Nothing is reported before that, or
	 * when the creation fails.
	 */
	if (dev->rtnl_link_initializing)
		return;

	skb = nlmsg_new(sr6_fdb_nlmsg_size(rd), GFP_KERNEL);
	if (!skb)
		goto errout;

	err = sr6_fdb_info(skb, dev, fdb, rd, 0, 0, type, 0);
	if (err) {
		/* sr6_fdb_nlmsg_size() is wrong */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}

	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_KERNEL);
	return;

errout:
	rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}

/* Largest encoded SRH among the installed remotes, skipping one of them. */
static int sr6_fdb_max_srhlen(struct sr6_priv *priv,
			      const struct sr6_remote *skip)
{
	struct sr6_remote *rd;
	struct sr6_fdb *fdb;
	int srhlen = 0;

	hlist_for_each_entry(fdb, &priv->fdb_list, node)
		list_for_each_entry(rd, &fdb->remotes, list)
			if (rd != skip)
				srhlen = max(srhlen,
					     sr6_encap_srhlen(rd->srh,
							      rd->encap_mode));

	return srhlen;
}

/* Recompute max_mtu and needed_headroom from the installed remotes, after
 * every change of the FDB. The current MTU is never changed here: a remote
 * that would not fit it was refused by sr6_fdb_check_mtu(), so the MTU never
 * exceeds the new maximum.
 */
static void sr6_fdb_update_limits(struct net_device *dev)
{
	int srhlen = sr6_fdb_max_srhlen(netdev_priv(dev), NULL);

	dev->max_mtu = sr6_max_mtu(srhlen);
	/* Only a hint: the encapsulation helpers expand each skb as needed. */
	WRITE_ONCE(dev->needed_headroom,
		   LL_MAX_HEADER + sizeof(struct ipv6hdr) + srhlen);
}

static int sr6_fdb_check_mtu(struct net_device *dev,
			     const struct sr6_policy *pol,
			     struct netlink_ext_ack *extack)
{
	int srhlen = sr6_encap_srhlen(pol->srh, pol->encap_mode);

	if (dev->mtu > sr6_max_mtu(srhlen)) {
		NL_SET_ERR_MSG(extack, "Device MTU is too large for this SRH");
		return -EINVAL;
	}

	return 0;
}

static struct sr6_fdb *sr6_fdb_alloc(const u8 *addr, u16 state)
{
	struct sr6_fdb *fdb;

	fdb = kzalloc_obj(*fdb);
	if (!fdb)
		return NULL;

	INIT_LIST_HEAD(&fdb->remotes);
	ether_addr_copy(fdb->addr, addr);
	fdb->state = state;

	return fdb;
}

/* Remove a whole entry, reporting each of its remotes. */
static void sr6_fdb_destroy(struct net_device *dev, struct sr6_fdb *fdb)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_remote *rd, *tmp;

	rhashtable_remove_fast(&priv->fdb_hash, &fdb->rhnode,
			       sr6_fdb_rht_params);
	hlist_del_rcu(&fdb->node);

	list_for_each_entry_safe(rd, tmp, &fdb->remotes, list) {
		sr6_fdb_notify(dev, fdb, rd, RTM_DELNEIGH);
		list_del_rcu(&rd->list);
		call_rcu(&rd->rcu, sr6_remote_free_rcu);
	}

	kfree_rcu(fdb, rcu);
}

static void sr6_fdb_flush(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct hlist_node *tmp;
	struct sr6_fdb *fdb;

	hlist_for_each_entry_safe(fdb, tmp, &priv->fdb_list, node)
		sr6_fdb_destroy(dev, fdb);
}

static int sr6_fdb_init(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);
	int err;

	err = rhashtable_init(&priv->fdb_hash, &sr6_fdb_rht_params);
	if (err)
		return err;

	INIT_HLIST_HEAD(&priv->fdb_list);
	priv->fdb_ready = true;

	return 0;
}

/* Reached from ndo_uninit and from the error path of newlink, which may follow
 * an ndo_uninit call in register_netdevice(), so it has to be safe against
 * running twice.
 */
static void sr6_fdb_fini(struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);

	if (!priv->fdb_ready)
		return;

	sr6_fdb_flush(dev);
	rhashtable_destroy(&priv->fdb_hash);
	priv->fdb_ready = false;
}

/* Install a remote built from pol. old, when set, is a remote of fdb that the
 * new one takes the place of, atomically for readers.
 */
static int sr6_fdb_install(struct net_device *dev, struct sr6_fdb *fdb,
			   struct sr6_remote *old,
			   const struct sr6_policy *pol)
{
	struct sr6_remote *rd;

	rd = sr6_remote_create(pol);
	if (!rd)
		return -ENOMEM;

	if (old) {
		list_replace_rcu(&old->list, &rd->list);
		/* A listener tracks remotes by SRH and table. */
		if (!sr6_remote_match(old, pol))
			sr6_fdb_notify(dev, fdb, old, RTM_DELNEIGH);
		call_rcu(&old->rcu, sr6_remote_free_rcu);
	} else {
		list_add_tail_rcu(&rd->list, &fdb->remotes);
	}

	sr6_fdb_notify(dev, fdb, rd, RTM_NEWNEIGH);

	return 0;
}

/* Create an entry with a single remote. The remote is linked before the entry
 * is published, so a reader never finds an empty entry.
 */
static int sr6_fdb_create(struct net_device *dev, const u8 *addr, u16 state,
			  const struct sr6_policy *pol)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_remote *rd;
	struct sr6_fdb *fdb;
	int err;

	fdb = sr6_fdb_alloc(addr, state);
	if (!fdb)
		return -ENOMEM;

	rd = sr6_remote_create(pol);
	if (!rd) {
		err = -ENOMEM;
		goto free_fdb;
	}
	list_add_tail(&rd->list, &fdb->remotes);

	err = rhashtable_lookup_insert_fast(&priv->fdb_hash, &fdb->rhnode,
					    sr6_fdb_rht_params);
	if (err)
		goto free_remote;

	hlist_add_head_rcu(&fdb->node, &priv->fdb_list);
	sr6_fdb_notify(dev, fdb, rd, RTM_NEWNEIGH);

	return 0;

free_remote:
	sr6_remote_free(rd);
free_fdb:
	kfree(fdb);
	return err;
}

/* Add or replace the remote of an entry. Mode and table are part of the
 * policy and replaced along with the SRH. They are never inherited from the
 * remote being replaced.
 */
static int sr6_fdb_update(struct net_device *dev, const u8 *addr, u16 state,
			  u16 flags, const struct sr6_policy *pol,
			  struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_fdb *fdb;
	int err;

	ASSERT_RTNL();

	err = sr6_fdb_check_mtu(dev, pol, extack);
	if (err)
		return err;

	fdb = sr6_fdb_find(priv, addr);
	if (!fdb) {
		if (!(flags & NLM_F_CREATE)) {
			NL_SET_ERR_MSG(extack, "FDB entry not found");
			return -ENOENT;
		}

		err = sr6_fdb_create(dev, addr, state, pol);
		goto out;
	}

	if (flags & NLM_F_EXCL || !(flags & NLM_F_REPLACE)) {
		NL_SET_ERR_MSG(extack, "FDB entry already exists");
		return -EEXIST;
	}

	WRITE_ONCE(fdb->state, state);
	err = sr6_fdb_install(dev, fdb, sr6_fdb_first(fdb), pol);

out:
	if (!err)
		sr6_fdb_update_limits(dev);

	return err;
}

/* A delete selector identifies a remote by SRH and table. It may repeat the
 * mode of the remote, which is ignored.
 */
static const struct nla_policy sr6_sel_policy[NDA_SR6_MAX + 1] = {
	[NDA_SR6_SRH]		= NLA_POLICY_MIN_LEN(sizeof(struct ipv6_sr_hdr) +
						     sizeof(struct in6_addr)),
	[NDA_SR6_MODE]		= NLA_POLICY_MAX(NLA_U8, SR6_ENCAP_MODE_MAX),
	[NDA_SR6_TABLE]		= { .type = NLA_U32 },
};

static const struct nla_policy sr6_fdb_policy[NDA_SR6_MAX + 1] = {
	[NDA_SR6_SRH]		= NLA_POLICY_MIN_LEN(sizeof(struct ipv6_sr_hdr) +
						     sizeof(struct in6_addr)),
	[NDA_SR6_MODE]		= NLA_POLICY_MAX(NLA_U8, SR6_ENCAP_MODE_MAX),
	[NDA_SR6_TABLE]		= { .type = NLA_U32 },
};

/* Whatever the mode, userspace configures the full SID list and never a
 * reduced SRH.
 */
static int sr6_parse_srh(const struct nlattr *attr, struct sr6_policy *pol,
			 struct netlink_ext_ack *extack)
{
	struct ipv6_sr_hdr *srh;

	if (!attr) {
		NL_SET_ERR_MSG(extack, "SRH with segment list is required");
		return -EINVAL;
	}

	srh = nla_data(attr);
	if (!seg6_validate_srh(srh, nla_len(attr), false)) {
		NL_SET_ERR_MSG_ATTR(extack, attr, "Invalid SRH");
		return -EINVAL;
	}

	pol->srh = srh;

	return 0;
}

/* Fill pol from a complete policy: an omitted mode is the full one and an
 * omitted or zero table is the routing context inherited from the device.
 */
static int sr6_parse_policy(struct nlattr *srh, struct nlattr *mode,
			    struct nlattr *table, struct sr6_policy *pol,
			    struct netlink_ext_ack *extack)
{
	pol->encap_mode = nla_get_u8_default(mode, SR6_ENCAP_MODE_FULL);
	pol->fib_table = nla_get_u32_default(table, 0);

	return sr6_parse_srh(srh, pol, extack);
}

static int sr6_fdb_parse(struct nlattr *tb[], struct sr6_policy *pol,
			 struct netlink_ext_ack *extack)
{
	struct nlattr *sr6[NDA_SR6_MAX + 1];
	int err;

	if (!tb[NDA_SR6]) {
		NL_SET_ERR_MSG(extack, "sr6 policy is required");
		return -EINVAL;
	}

	err = nla_parse_nested(sr6, NDA_SR6_MAX, tb[NDA_SR6], sr6_fdb_policy,
			       extack);
	if (err)
		return err;

	return sr6_parse_policy(sr6[NDA_SR6_SRH], sr6[NDA_SR6_MODE],
				sr6[NDA_SR6_TABLE], pol, extack);
}

/* Parse the optional selector of a delete request. */
static int sr6_fdb_parse_sel(struct nlattr *tb[], struct sr6_policy *sel,
			     bool *has_sel, struct netlink_ext_ack *extack)
{
	struct nlattr *sr6[NDA_SR6_MAX + 1];
	int err;

	*has_sel = false;

	if (!tb[NDA_SR6])
		return 0;

	err = nla_parse_nested(sr6, NDA_SR6_MAX, tb[NDA_SR6],
			       sr6_sel_policy, extack);
	if (err)
		return err;

	err = sr6_parse_policy(sr6[NDA_SR6_SRH], NULL, sr6[NDA_SR6_TABLE],
			       sel, extack);
	if (err)
		return err;

	*has_sel = true;

	return 0;
}

static int sr6_fdb_validate(struct nlattr *tb[], const u8 *addr, u16 vid,
			    struct netlink_ext_ack *extack)
{
	int i;

	if (!is_zero_ether_addr(addr) && !is_valid_ether_addr(addr)) {
		NL_SET_ERR_MSG(extack,
			       "Only unicast and all-zeros MAC addresses are supported");
		return -EINVAL;
	}

	if (vid) {
		NL_SET_ERR_MSG(extack, "VLAN-qualified FDB entries are not supported");
		return -EOPNOTSUPP;
	}

	for (i = 0; i <= NDA_MAX; i++) {
		if (!tb[i] || i == NDA_LLADDR || i == NDA_SR6)
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
	struct sr6_policy pol;
	int err;

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

	err = sr6_fdb_parse(tb, &pol, extack);
	if (err)
		return err;

	err = sr6_fdb_update(dev, addr, ndm->ndm_state, flags, &pol, extack);
	if (!err)
		*notified = true;

	return err;
}

static int sr6_fdb_del(struct ndmsg *ndm, struct nlattr *tb[],
		       struct net_device *dev, const unsigned char *addr,
		       u16 vid, bool *notified, struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_policy sel;
	struct sr6_fdb *fdb;
	bool has_sel;
	int err;

	ASSERT_RTNL();

	err = sr6_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;

	if (ndm->ndm_flags & ~NTF_SELF)
		return -EOPNOTSUPP;

	err = sr6_fdb_parse_sel(tb, &sel, &has_sel, extack);
	if (err)
		return err;

	fdb = sr6_fdb_find(priv, addr);
	if (!fdb)
		return -ENOENT;

	if (has_sel && !sr6_remote_match(sr6_fdb_first(fdb), &sel))
		return -ENOENT;

	sr6_fdb_destroy(dev, fdb);
	sr6_fdb_update_limits(dev);
	*notified = true;
	return 0;
}

/* Entries carry no per-entry NTF flags. Once a nonzero ndm_flags filter has
 * been rejected as unsupported, NDA_NDM_FLAGS_MASK therefore selects the
 * entries whose requested flag bits are clear, which is all of them.
 */
static const struct nla_policy sr6_del_bulk_policy[NDA_MAX + 1] = {
	[NDA_NDM_STATE_MASK]	= { .type = NLA_U16 },
	[NDA_NDM_FLAGS_MASK]	= { .type = NLA_U8 },
};

static int sr6_fdb_del_bulk(struct nlmsghdr *nlh, struct net_device *dev,
			    struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct ndmsg *ndm = nlmsg_data(nlh);
	struct nlattr *tb[NDA_MAX + 1];
	struct hlist_node *tmp;
	struct sr6_fdb *fdb;
	u16 state_mask = 0;
	int err;

	ASSERT_RTNL();

	err = nlmsg_parse(nlh, sizeof(*ndm), tb, NDA_MAX, sr6_del_bulk_policy,
			  extack);
	if (err)
		return err;

	/* NTF_MASTER and NTF_SELF select the table, they do not filter it. */
	if (ndm->ndm_flags & ~(NTF_MASTER | NTF_SELF)) {
		NL_SET_ERR_MSG(extack, "Unsupported sr6 FDB flush flags");
		return -EOPNOTSUPP;
	}

	if (ndm->ndm_state & ~(NUD_PERMANENT | NUD_REACHABLE | NUD_NOARP)) {
		NL_SET_ERR_MSG(extack, "Unsupported sr6 FDB flush state");
		return -EINVAL;
	}

	if (tb[NDA_NDM_STATE_MASK])
		state_mask = nla_get_u16(tb[NDA_NDM_STATE_MASK]);

	/* Without a mask, a state would silently select every entry. */
	if (ndm->ndm_state && !state_mask) {
		NL_SET_ERR_MSG(extack, "sr6 FDB flush state requires a state mask");
		return -EINVAL;
	}

	hlist_for_each_entry_safe(fdb, tmp, &priv->fdb_list, node) {
		if (state_mask && (fdb->state & state_mask) != ndm->ndm_state)
			continue;
		sr6_fdb_destroy(dev, fdb);
	}

	sr6_fdb_update_limits(dev);

	return 0;
}

/* One message per remote. The index counts remotes rather than entries. */
static int sr6_fdb_dump(struct sk_buff *skb, struct netlink_callback *cb,
			struct net_device *dev, struct net_device *filter_dev,
			int *idx)
{
	struct ndo_fdb_dump_context *ctx = (void *)cb->ctx;
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_remote *rd;
	struct sr6_fdb *fdb;
	int err = 0;

	rcu_read_lock();
	hlist_for_each_entry_rcu(fdb, &priv->fdb_list, node) {
		list_for_each_entry_rcu(rd, &fdb->remotes, list) {
			if (*idx < ctx->fdb_idx)
				goto skip;

			err = sr6_fdb_info(skb, dev, fdb, rd,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, RTM_NEWNEIGH,
					   NLM_F_MULTI);
			if (err)
				goto out;
skip:
			++*idx;
		}
	}
out:
	rcu_read_unlock();
	return err;
}

/* A get request carries a single MAC and returns its remote. */
static int sr6_fdb_get(struct sk_buff *skb, struct nlattr *tb[],
		       struct net_device *dev, const unsigned char *addr,
		       u16 vid, u32 portid, u32 seq,
		       struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	struct sr6_remote *rd;
	struct sr6_fdb *fdb;
	int err;

	err = sr6_fdb_validate(tb, addr, vid, extack);
	if (err)
		return err;

	rcu_read_lock();
	fdb = sr6_fdb_find(priv, addr);
	rd = fdb ? sr6_fdb_first(fdb) : NULL;
	err = rd ? sr6_fdb_info(skb, dev, fdb, rd, portid, seq,
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

/* Resolve the route to the first SID, through the FIB table of the remote or,
 * when none is set, through the VRF context inherited from the device
 * hierarchy. Mirrors seg6_output_dst_lookup() in seg6_iptunnel.c.
 *
 * Always returns a dst with a refcount held. A failure is reported through
 * dst->error, never as NULL.
 */
static struct dst_entry *sr6_dst_lookup(struct net *net,
					struct net_device *dev,
					const struct sr6_remote *rd,
					struct flowi6 *fl6)
{
	struct dst_entry *dst;

	if (rd->fib_table) {
		dst = sr6_table_lookup(net, rd->fib_table, fl6);
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
					  struct sr6_remote *rd)
{
	struct dst_entry *dst;
	struct flowi6 fl6;
	struct net *net;
	int err;

	local_bh_disable();
	dst = dst_cache_get(&rd->dst_cache);
	local_bh_enable();

	if (likely(dst))
		return dst;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = rd->srh->segments[rd->srh->first_segment];

	net = dev_net(dev);
	dst = sr6_dst_lookup(net, dev, rd, &fl6);
	if (dst->error) {
		err = dst->error;
		goto release_dst;
	}

	if (dst_dev(dst) == dev) {
		err = -ELOOP;
		goto release_dst;
	}

	local_bh_disable();
	dst_cache_set_ip6(&rd->dst_cache, dst, &fl6.saddr);
	local_bh_enable();

	return dst;

release_dst:
	dst_release(dst);
	return ERR_PTR(err);
}

/* Encapsulate an L2 frame in IPv6+SRH toward one remote and transmit it.
 * Consumes the skb. skb->data points to the Ethernet header.
 */
static void sr6_xmit_one(struct sk_buff *skb, struct net_device *dev,
			 struct sr6_remote *rd)
{
	enum skb_drop_reason reason;
	struct dst_entry *dst;
	int pkt_len;
	int err;

	dst = sr6_route_lookup(dev, rd);
	if (IS_ERR(dst)) {
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

	if (rd->encap_mode == SR6_ENCAP_MODE_REDUCED)
		err = seg6_do_srh_encap_red(skb, rd->srh, IPPROTO_ETHERNET);
	else
		err = seg6_do_srh_encap(skb, rd->srh, IPPROTO_ETHERNET);

	if (unlikely(err)) {
		DEV_STATS_INC(dev, tx_errors);
		reason = (err == -ENOMEM) ? SKB_DROP_REASON_NOMEM
					  : SKB_DROP_REASON_NOT_SPECIFIED;
		goto free_skb;
	}

	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	sr6_tunnel_xmit(skb, dev, pkt_len);

	return;

free_skb:
	kfree_skb_reason(skb, reason);
}

/* Select the FDB entry by destination MAC, falling back to the all-zeros
 * entry, and send the frame to its remote.
 *
 * An exact match never falls back, even when its route lookup fails: that
 * would send the frame along a policy that userspace did not select for it.
 */
static netdev_tx_t sr6_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct sr6_priv *priv = netdev_priv(dev);
	enum skb_drop_reason reason;
	struct sr6_remote *rd;
	struct sr6_fdb *fdb;

	/* seg6_do_srh_encap() and seg6_do_srh_encap_red() read the traffic
	 * class, the flow label and the hop limit of an inner IPv6 header,
	 * which may not be in the linear area yet. The Ethernet header is
	 * pulled with it.
	 */
	reason = pskb_may_pull_reason(skb, ETH_HLEN);
	if (unlikely(reason))
		goto drop;

	reason = pskb_inet_may_pull_reason(skb);
	if (unlikely(reason))
		goto drop;

	rcu_read_lock();

	fdb = sr6_fdb_find(priv, skb->data);
	if (!fdb)
		fdb = sr6_fdb_find(priv, sr6_zero_mac);

	/* Empty only while a concurrent delete is unlinking the entry. */
	rd = fdb ? sr6_fdb_first(fdb) : NULL;
	if (unlikely(!rd)) {
		rcu_read_unlock();
		reason = SKB_DROP_REASON_NO_TX_TARGET;
		goto drop;
	}

	sr6_xmit_one(skb, dev, rd);

	rcu_read_unlock();

	return NETDEV_TX_OK;

drop:
	DEV_STATS_INC(dev, tx_dropped);
	kfree_skb_reason(skb, reason);
	return NETDEV_TX_OK;
}

static void sr6_dev_uninit(struct net_device *dev)
{
	sr6_fdb_fini(dev);
}

static const struct net_device_ops sr6_netdev_ops = {
	.ndo_uninit		= sr6_dev_uninit,
	.ndo_start_xmit		= sr6_xmit,
	.ndo_fdb_add		= sr6_fdb_add,
	.ndo_fdb_del		= sr6_fdb_del,
	.ndo_fdb_del_bulk	= sr6_fdb_del_bulk,
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

	/* The device carries an SRv6 tunnel bound to a routing context. Moving
	 * it to another netns would break that context and the dst_cache.
	 */
	dev->netns_immutable = true;

	eth_hw_addr_random(dev);
}

static const struct nla_policy sr6_policy[IFLA_SR6_MAX + 1] = {
	[IFLA_SR6_SRH]		= NLA_POLICY_MIN_LEN(sizeof(struct ipv6_sr_hdr) +
						     sizeof(struct in6_addr)),
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

	return 0;
}

/* The remote that ip link configures and reports: the only remote of the
 * all-zeros entry. NULL when there is no such entry or it has several.
 */
static struct sr6_remote *sr6_link_remote(const struct net_device *dev)
{
	struct sr6_fdb *fdb;

	fdb = sr6_fdb_find(netdev_priv(dev), sr6_zero_mac);
	if (!fdb || !list_is_singular(&fdb->remotes))
		return NULL;

	return list_first_entry(&fdb->remotes, struct sr6_remote, list);
}

/* ip link helpers configure the all-zeros FDB entry. Unlike the FDB
 * interface, they keep the mode and the table of the remote they replace
 * when the request leaves them out. Without one, the defaults apply.
 */
static int sr6_link_policy(struct nlattr *data[], const struct sr6_remote *old,
			   struct sr6_policy *pol,
			   struct netlink_ext_ack *extack)
{
	int err;

	err = sr6_parse_policy(data[IFLA_SR6_SRH], data[IFLA_SR6_ENCAP_MODE],
			       data[IFLA_SR6_FIB_TABLE], pol, extack);
	if (err || !old)
		return err;

	if (!data[IFLA_SR6_ENCAP_MODE])
		pol->encap_mode = old->encap_mode;
	if (!data[IFLA_SR6_FIB_TABLE])
		pol->fib_table = old->fib_table;

	return 0;
}

/* Mode and table describe a policy and are refused without its SRH. */
static bool sr6_link_has_policy(struct nlattr *data[])
{
	return data && (data[IFLA_SR6_SRH] || data[IFLA_SR6_ENCAP_MODE] ||
			data[IFLA_SR6_FIB_TABLE]);
}

/* Check an MTU given in a link request against the encapsulation limit. The
 * core checked it already, but before the SRH was known.
 */
static int sr6_check_link_mtu(struct net_device *dev, struct nlattr *tb[],
			      int max_mtu, struct netlink_ext_ack *extack)
{
	u32 mtu;

	if (!tb[IFLA_MTU])
		return 0;

	mtu = nla_get_u32(tb[IFLA_MTU]);
	if (mtu > max_mtu) {
		NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_MTU],
				    "MTU exceeds the encapsulation limit");
		return -EINVAL;
	}

	if (mtu < dev->min_mtu) {
		NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_MTU],
				    "MTU below the device minimum");
		return -EINVAL;
	}

	return 0;
}

/* Without a policy, the device starts with an empty FDB and the default MTU
 * of a single SID in the full mode. With one, it is installed as the only
 * remote of the all-zeros entry, and the MTU follows its overhead. A
 * user-supplied MTU above the limit is refused, not lowered.
 *
 * The policy is installed before the device is registered, so that the
 * RTM_NEWLINK the core sends after newlink() reports it along with the final
 * max_mtu. sr6_fdb_notify() stays silent until then.
 */
static int sr6_newlink(struct net_device *dev,
		       struct rtnl_newlink_params *params,
		       struct netlink_ext_ack *extack)
{
	int srhlen = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr);
	struct nlattr **data = params->data;
	struct nlattr **tb = params->tb;
	struct sr6_policy pol;
	int max_srhlen = 0;
	bool has_pol;
	int err;

	has_pol = sr6_link_has_policy(data);
	if (has_pol) {
		err = sr6_link_policy(data, NULL, &pol, extack);
		if (err)
			return err;
		srhlen = sr6_encap_srhlen(pol.srh, pol.encap_mode);
		max_srhlen = srhlen;
	}

	err = sr6_check_link_mtu(dev, tb, sr6_max_mtu(max_srhlen), extack);
	if (err)
		return err;

	if (!tb[IFLA_MTU])
		dev->mtu = sr6_default_mtu(srhlen);

	err = sr6_fdb_init(dev);
	if (err)
		return err;

	if (has_pol) {
		err = sr6_fdb_update(dev, sr6_zero_mac,
				     NUD_NOARP | NUD_PERMANENT,
				     NLM_F_CREATE | NLM_F_EXCL, &pol, extack);
		if (err)
			goto fini;
	} else {
		sr6_fdb_update_limits(dev);
	}

	err = register_netdevice(dev);
	if (err)
		goto fini;

	return 0;

fini:
	/* register_netdevice() calls ndo_uninit only on some of its error
	 * paths.
	 */
	sr6_fdb_fini(dev);
	return err;
}

/* Create the all-zeros entry or replace its remote. A mode or table left out
 * of the request is kept from the remote being replaced.
 *
 * Unlike an FDB update, a link change may carry an MTU. Without one, the MTU
 * is recomputed as the default for the largest overhead among the remotes
 * that remain, as it was when the device held a single policy.
 */
static int sr6_changelink(struct net_device *dev, struct nlattr *tb[],
			  struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	struct sr6_priv *priv = netdev_priv(dev);
	int old_max_mtu = dev->max_mtu;
	struct sr6_remote *old = NULL;
	int old_mtu = dev->mtu;
	struct sr6_policy pol;
	struct sr6_fdb *fdb;
	int srhlen, mtu;
	int err;

	if (!sr6_link_has_policy(data))
		return 0;

	fdb = sr6_fdb_find(priv, sr6_zero_mac);
	if (fdb)
		old = sr6_fdb_first(fdb);

	err = sr6_link_policy(data, old, &pol, extack);
	if (err)
		return err;

	srhlen = max(sr6_fdb_max_srhlen(priv, old),
		     sr6_encap_srhlen(pol.srh, pol.encap_mode));

	err = sr6_check_link_mtu(dev, tb, sr6_max_mtu(srhlen), extack);
	if (err)
		return err;

	mtu = tb[IFLA_MTU] ? nla_get_u32(tb[IFLA_MTU]) :
			     sr6_default_mtu(srhlen);

	/* netif_set_mtu() checks against max_mtu, which a shorter SRH raises.
	 * do_setlink() then finds the MTU of the request in place.
	 */
	dev->max_mtu = sr6_max_mtu(srhlen);
	err = netif_set_mtu(dev, mtu);
	if (err)
		goto restore;

	err = sr6_fdb_update(dev, sr6_zero_mac, NUD_NOARP | NUD_PERMANENT,
			     NLM_F_CREATE | NLM_F_REPLACE, &pol, extack);
	if (err)
		goto restore;

	return 0;

restore:
	dev->max_mtu = old_max_mtu;
	netif_set_mtu(dev, old_mtu);
	return err;
}

static void sr6_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}

/* Link dumps report the policy that ip link configures, as long as the
 * all-zeros entry has a single remote. The FDB reports every policy.
 * Both run under RTNL, through rtnl_fill_ifinfo() and if_nlmsg_size().
 */
static size_t sr6_get_size(const struct net_device *dev)
{
	const struct sr6_remote *rd = sr6_link_remote(dev);

	if (!rd)
		return 0;

	return nla_total_size(ipv6_optlen(rd->srh))	/* IFLA_SR6_SRH */
	       + nla_total_size(4)			/* IFLA_SR6_FIB_TABLE */
	       + nla_total_size(1);			/* IFLA_SR6_ENCAP_MODE */
}

static int sr6_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct sr6_remote *rd = sr6_link_remote(dev);

	if (!rd)
		return 0;

	if (nla_put(skb, IFLA_SR6_SRH, ipv6_optlen(rd->srh), rd->srh) ||
	    (rd->fib_table &&
	     nla_put_u32(skb, IFLA_SR6_FIB_TABLE, rd->fib_table)) ||
	    nla_put_u8(skb, IFLA_SR6_ENCAP_MODE, rd->encap_mode))
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
	.changelink	= sr6_changelink,
	.dellink	= sr6_dellink,
	.get_size	= sr6_get_size,
	.fill_info	= sr6_fill_info,
};

static int sr6_reset_dst_cache(struct net_device *dev,
			       struct netdev_nested_priv *priv)
{
	struct sr6_remote *rd;
	struct sr6_priv *sp;
	struct sr6_fdb *fdb;

	if (!netif_is_sr6(dev))
		return 0;

	sp = netdev_priv(dev);
	hlist_for_each_entry(fdb, &sp->fdb_list, node)
		list_for_each_entry(rd, &fdb->remotes, list)
			dst_cache_reset(&rd->dst_cache);

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

	/* Remote callbacks may outlive their devices and execute module code.
	 * A grace period does not wait for callbacks.
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
