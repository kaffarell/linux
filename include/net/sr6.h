/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NET_SR6_H
#define __NET_SR6_H

#include <linux/netdevice.h>

static inline bool netif_is_sr6(const struct net_device *dev)
{
	return dev->rtnl_link_ops &&
	       !strcmp(dev->rtnl_link_ops->kind, "sr6");
}

#endif
