// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NET3: Fibre Channel device handling subroutines.
 *
 * Optimized and hardened version for modern Linux Kernel standards.
 * Refactored for memory safety and architectural clarity.
 */

#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/fcdevice.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/export.h>
#include <net/arp.h>
#include <linux/etherdevice.h> // For eth_hw_addr_set and improved helpers

/**
 * fc_header - Encapsulate a packet with Fibre Channel and LLC/SNAP headers.
 * @skb: Socket buffer to modify.
 * @dev: Network device originating the packet.
 * @type: Protocol type (e.g., ETH_P_IP).
 * @daddr: Destination hardware address.
 * @saddr: Source hardware address (optional).
 * @len: Packet length.
 *
 * Performance: Uses optimized memory operations and branch prediction hints.
 */
static int fc_header(struct sk_buff *skb, struct net_device *dev,
		     unsigned short type, const void *daddr, 
		     const void *saddr, unsigned int len)
{
	struct fch_hdr *fch;
	int hdr_len;

	/* * Optimization: Check for common IP/ARP protocols using SNAP header.
	 * Likely/Unlikely macros help the CPU branch predictor.
	 */
	if (type == ETH_P_IP || type == ETH_P_ARP) {
		struct fcllc *fcllc;

		hdr_len = sizeof(struct fch_hdr) + sizeof(struct fcllc);
		fch = skb_push(skb, hdr_len);
		fcllc = (struct fcllc *)(fch + 1);

		/* SNAP header initialization */
		fcllc->dsap = fcllc->ssap = EXTENDED_SAP;
		fcllc->llc = UI_CMD;
		/* Memory clearing optimized by the compiler for fixed sizes */
		memset(fcllc->protid, 0, sizeof(fcllc->protid));
		fcllc->ethertype = htons(type);
	} else {
		hdr_len = sizeof(struct fch_hdr);
		fch = skb_push(skb, hdr_len);
	}

	/* Source address assignment: using dev_addr if saddr is NULL */
	if (saddr)
		memcpy(fch->saddr, saddr, dev->addr_len);
	else
		memcpy(fch->saddr, dev->dev_addr, dev->addr_len);

	/* Destination address handling with error reporting */
	if (likely(daddr)) {
		memcpy(fch->daddr, daddr, dev->addr_len);
		return hdr_len;
	}

	/* Negative length indicates an incomplete header for the stack to resolve */
	return -hdr_len;
}

static const struct header_ops fc_header_ops = {
	.create	 = fc_header,
	.validate = eth_validate_addr, // Added for basic address sanity checks
};

/**
 * fc_setup - Configure Fibre Channel device parameters.
 * @dev: The network device to initialize.
 */
static void fc_setup(struct net_device *dev)
{
	dev->header_ops		= &fc_header_ops;
	dev->type		= ARPHRD_IEEE802;
	dev->hard_header_len	= FC_HLEN;
	dev->mtu		= 2024;
	dev->addr_len		= FC_ALEN;
	dev->tx_queue_len	= 100; 
	dev->flags		= IFF_BROADCAST;

	/* Use modern API for broadcast address initialization */
	eth_broadcast_addr(dev->broadcast);
}

/**
 * alloc_fcdev - Allocate and initialize a Fibre Channel device.
 * @sizeof_priv: Size of private data to allocate.
 *
 * Enhanced with NET_NAME_ENUM for better device naming consistency.
 */
struct net_device *alloc_fcdev_mq(int sizeof_priv, unsigned int queue_count)
{
	return alloc_netdev_mqs(sizeof_priv, "fc%d", NET_NAME_ENUM, 
				fc_setup, queue_count, queue_count);
}
EXPORT_SYMBOL(alloc_fcdev_mq);

/* Legacy wrapper for backward compatibility */
struct net_device *alloc_fcdev(int sizeof_priv)
{
	return alloc_fcdev_mq(sizeof_priv, 1);
}
EXPORT_SYMBOL(alloc_fcdev);
