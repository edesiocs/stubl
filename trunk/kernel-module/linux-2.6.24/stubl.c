/*
 * Stubl - IPv6 Stateless Tunnel Broker for LANs.
 * Copyright 2008 Google Inc.
 *
 * Authors:
 *	Paul Marks		<pmarks@google.com>
 *
 * Derived from the Linux "sit" module.  Original authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *	Roger Venning		<r.venning@telstra.com>
 *	Nate Thompson		<nate@thebog.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/crypto.h>
#include <linux/ctype.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/ipip.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>
#include <net/dsfield.h>

/*
   This version of net/ipv6/sit.c is cloned of net/ipv4/ip_gre.c

   For comments look at net/ipv4/ip_gre.c --ANK
 */


static int ipip6_fb_tunnel_init(struct net_device *dev);
static void ipip6_tunnel_setup(struct net_device *dev);

static struct net_device *ipip6_fb_tunnel_dev;
static struct ip_tunnel *tunnels_wc[1];


/* Spinlock for writing to parameters.  (Use RCU for reading) */
static DEFINE_SPINLOCK(param_write_lock);

/* Blowfish cipher for unscrambling address suffixes. */
static struct crypto_cipher *tunnel_key = NULL;

/* 64-bit tunnel prefix, array of 4 16-bit chunks. */
static const __be16 *tunnel_prefix = NULL;

/* List of subnets which are allowed to be tunnel endpoints. */
struct ipv4_subnet_list {
	size_t size;
	struct ipv4_subnet {
		__be32 ip;
		__be32 mask;
	} entry[];
};
static const struct ipv4_subnet_list *allowed_subnets;


/* === Functions for parameter string handling === */

/* If the input string starts with 2 hex digits, then return the
 * integer value (0-255) and advance the pointer by 2.
 * Otherwise, return -1.
 */
static int parse_hex_byte(const char **s)
{
	char buf[3];
	if (isxdigit((*s)[0]) && isxdigit((*s)[1])) {
		memcpy(buf, *s, 2);
		*s += 2;
		buf[2] = '\0';
		return simple_strtoul(buf, NULL, 16);
	}
	return -1;
}

/* Consume a string of digits from the beginning of a buffer.  The number of
 * digits must be between 1..max_len, followed by a non-digit.  If successful,
 * return the value and advance the pointer by the number of digits consumed.
 * Otherwise, return -1.
 */
static int parse_digits(const char **s, unsigned int base, ptrdiff_t max_len)
{
	char *endp;
	const int value = simple_strtoul(*s, &endp, base);
	const ptrdiff_t len = endp - *s;
	if (!(1 <= len && len <= max_len))
		return -1;
	*s = endp;
	return value;
}

/* Parse pairs of hex digits into a byte array.  If successful, returns
 * the number of bytes generated.  On error, returns a negative number.
 */
static int parse_hex_string(const char *in, u8 *out, int max_len)
{
	int len = 0;
	int cur_byte;

	while (*in != '\0') {
		/* Ignore whitespace between bytes */
		if (isspace(*in)) {
			in++;
			continue;
		}

		/* Try to parse a 2-digit hex byte */
		cur_byte = parse_hex_byte(&in);
		if (cur_byte < 0)
			return -EINVAL;
		if (len >= max_len)
			return -EFBIG;
		out[len++] = (u8)cur_byte;
	}
	return len;
}

/* Parse a 64-bit IPv6 prefix to an array of 8 bytes.
 * Input should be formatted like "aaaa:bbbb:cccc:dddd\n".
 * Return 0 if successful, negative on error.
 */
static int parse_ipv6_prefix64(const char *in, __be16 *out)
{
	int i;
	/* Get four 16-bit chunks. */
	for (i = 0; i < 4; i++) {
		/* Consume one chunk, abort on failure. */
		const int value = parse_digits(&in, 16, 4);
		if (value < 0)
			return -EINVAL;
		out[i] = cpu_to_be16(value);

		/* Every chunk but the last ends with a : */
		if (i < 3 && *in++ != ':')
			return -EINVAL;
	}

	/* Only whitespace is allowed at the end. */
	for (; *in != '\0'; in++)
		if (!isspace(*in))
			return -EINVAL;
	return 0;
}

/* Parse an IPv4 subnet, formatted like "192.168.0.0/24".  If successful,
 * advance the pointer by the number of chars parsed, write the subnet
 * info to *out, and return 0.  Otherwise, return a negative.
 */
static int parse_ipv4_subnet(const char **s, struct ipv4_subnet *out)
{
	int i;
	int mask_len;
	u8 *ip_bytes = (u8 *)&out->ip;

	/* Get IP address part. */
	for (i = 0; i < 4; i++) {
		const int value = parse_digits(s, 10, 3);
		if (value < 0 || value > 255)
			return -EINVAL;
		ip_bytes[i] = value;

		/* Every octet but the last ends with '.' */
		if (i < 3 && *(*s)++ != '.')
			return -EINVAL;
	}

	/* Parse /N from the end, or assume 32. */
	if (**s == '/') {
		(*s)++;
		mask_len = parse_digits(s, 10, 2);
	} else {
		mask_len = 32;
	}

	/* Convert mask length into a mask: 11111...000 */
	if (mask_len == 0) {
		out->mask = 0;
	} else if (1 <= mask_len && mask_len <= 32) {
		out->mask = cpu_to_be32(~0 << (32 - mask_len));
	} else {
		return -EINVAL;
	}

	/* Drop redundant bits from ip part. */
	out->ip &= out->mask;

	return 0;
}

/* Parse a series of IPv4 subnet strings, and any trailing whitespace.
 * If successful, put a kmalloc'd list in *out, and return 0.
 * Otherwise, return a negative.
 */
static int parse_ipv4_subnet_list(const char *in,
				  struct ipv4_subnet_list **out)
{
	const char *c;
	char last_c;
	struct ipv4_subnet_list *sl;
	size_t n_subnets;
	size_t i;
	int err = 0;

	/* Get expected number of subnets, by counting the number of
 	 * transitions from space to non-space. */
	n_subnets = 0;
	last_c = ' ';
	for (c = in; *c != '\0'; c++) {
		if (isspace(last_c) && !isspace(*c))
			n_subnets++;
		last_c = *c;
	}

	/* Allocate vector of subnets. */
	sl = kmalloc(sizeof(struct ipv4_subnet_list) +
		     n_subnets * sizeof(struct ipv4_subnet), GFP_KERNEL);
	if (sl == NULL)
		return -ENOMEM;

	/* Try to populate all the subnets. */
	sl->size = n_subnets;
	for (i = 0; i < n_subnets; i++) {
		err = parse_ipv4_subnet(&in, &sl->entry[i]);
		if (err < 0)
			goto out;

		/* Consume whitespace. */
		while (isspace(*in))
			in++;
	}

	/* We should have consumed the string exactly. */
	if (*in != '\0') {
		err = -EFAULT;
		goto out;
	}

	/* Yay, done! */
	*out = sl;
	return 0;
out:
	kfree(sl);
	return err;
}

/* Convert an IPv4 subnet to human-readable a.b.c.d/e format. */
static int ipv4_subnet_to_string(char *buffer, int size,
				 const struct ipv4_subnet *net)
{
	int mask_len;
	if (net->mask == 0) {
		mask_len = 0;
	} else {
		/* count trailing zeroes */
		mask_len = 32 - __builtin_ctz(be32_to_cpu(net->mask));
	}
	return snprintf(buffer, size, "%u.%u.%u.%u/%d",
			NIPQUAD(net->ip), mask_len);
}


/* === Functions for managing the address encryption cipher === */

/* Replace the cipher instance, and free the old one when readers have
 * abandoned it.
 */
static void update_cipher(struct crypto_cipher **cipher_ptr,
			  struct crypto_cipher *new_cipher)
{
	struct crypto_cipher *old_cipher;

	/* Perform RCU update */
	spin_lock(&param_write_lock);
	old_cipher = *cipher_ptr;
	rcu_assign_pointer(*cipher_ptr, new_cipher);
	spin_unlock(&param_write_lock);

	/* Free the old cipher when ready. */
	synchronize_rcu();
	crypto_free_cipher(old_cipher);
}

/* If a cipher is available, then decrypt in -> out, and return 0.
 * If no cipher is available, return a negative.
 */
static int try_decrypt64(struct crypto_cipher **cipher_ptr,
		         u8 *out, const u8 *in)
{
	struct crypto_cipher *cipher;
	int err = 0;

	rcu_read_lock();
	cipher = rcu_dereference(*cipher_ptr);
	if (cipher == NULL) {
		err = -ENOENT;
	} else {
		crypto_cipher_decrypt_one(cipher, out, in);
	}
	rcu_read_unlock();
	return err;
}

#define param_check_cipher_key(name, p) \
	__param_check(name, p, struct crypto_cipher *)

static int param_set_cipher_key(const char *val, struct kernel_param *kp)
{
	struct crypto_cipher *new_cipher;
	int key_len;
	u8 key[128];
	int err = 0;

	/* Try to convert the user's key to raw bytes. */
	key_len = parse_hex_string(val, key, ARRAY_SIZE(key));
	if (key_len < 0) {
		printk(KERN_INFO "stubl: Can't parse key.\n");
		return key_len;
	}

	/* If the key is empty, then clear it. */
	if (key_len == 0) {
		printk(KERN_INFO "stubl: Clearing tunnel key.\n");
		update_cipher(kp->arg, NULL);
		return 0;
	} 

	printk(KERN_INFO "stubl: Setting tunnel key.\n");

	/* Init a new cipher */
	new_cipher = crypto_alloc_cipher("blowfish", 0, 0);
	if (IS_ERR(new_cipher)) {
		printk(KERN_INFO "stubl: Can't init cipher: %ld\n",
				PTR_ERR(new_cipher));
		return PTR_ERR(new_cipher);
	}

	/* Set key */
	err = crypto_cipher_setkey(new_cipher, key, key_len);
	if (err < 0) {
		printk(KERN_INFO "stubl: Can't set key: %d\n", err);
		crypto_free_cipher(new_cipher);
		return err;
	}

	/* Perform RCU update */
	update_cipher(kp->arg, new_cipher);

	return 0;
}

static int param_get_cipher_key(char *buffer, struct kernel_param *kp)
{
	struct crypto_cipher **cipher_ptr = kp->arg;
	bool is_set;

	rcu_read_lock();
	is_set = (rcu_dereference(*cipher_ptr) != NULL);
	rcu_read_unlock();

	return snprintf(buffer, PAGE_SIZE, is_set ? "<set>" : "<not set>");
}


/* === Functions for managing the 64-bit IPv6 Tunnel Prefix === */

/* Replace the IPv6 prefix, and free the old one when readers have
 * abandoned it.
 */
static void update_ipv6_prefix(const __be16 **prefix_ptr,
			       const __be16 *new_prefix)
{
	const __be16 *old_prefix;

	/* Perform RCU update */
	spin_lock(&param_write_lock);
	old_prefix = *prefix_ptr;
	rcu_assign_pointer(*prefix_ptr, new_prefix);
	spin_unlock(&param_write_lock);

	/* Free the old prefix when ready. */
	synchronize_rcu();
	kfree(old_prefix);
}

/* If the given IPv6 address matches our configured prefix, return 0.
 * If there's a mismatch, or no prefix exists, return nonzero.
 */
static int compare_ipv6_prefix(const __be16 **prefix_ptr,
			       const struct in6_addr *v6addr)
{
	int res = -1;
	const __be16 *prefix;

	rcu_read_lock();
	prefix = rcu_dereference(*prefix_ptr);
	if (prefix != NULL)
		res = memcmp(v6addr, prefix, 8);
	rcu_read_unlock();

	return res;
}

#define param_check_ipv6_prefix(name, p) \
	__param_check(name, p, const __be16 *)

static int param_set_ipv6_prefix(const char *val, struct kernel_param *kp)
{
	int res;
	__be16 *new_prefix;

	/* Skip leading whitespace. */
	while (isspace(*val))
		val++;

	/* If input is empty, clear the prefix. */
	if (*val == '\0') {
		printk(KERN_INFO "stubl: Clearing tunnel prefix.\n");
		update_ipv6_prefix(kp->arg, NULL);
		return 0;
	}

	new_prefix = kmalloc(4 * sizeof(__be16), GFP_KERNEL);
	if (!new_prefix)
		return -ENOMEM;

	res = parse_ipv6_prefix64(val, new_prefix);
	if (res < 0) {
		printk(KERN_INFO "stubl: Can't parse tunnel prefix.\n");
		kfree(new_prefix);
		return res;
	}

	printk(KERN_INFO "stubl: Setting tunnel prefix.\n");

	/* Perform RCU update */
	update_ipv6_prefix(kp->arg, new_prefix);
	return 0;
}

static int param_get_ipv6_prefix(char *buffer, struct kernel_param *kp)
{
	const __be16 **prefix_ptr = kp->arg;
	const __be16 *prefix;
	__be16 prefix_copy[4];

	rcu_read_lock();
	prefix = rcu_dereference(*prefix_ptr);
	if (prefix != NULL)
		memcpy(prefix_copy, prefix, 4 * sizeof(__be16));
	rcu_read_unlock();

	/* If no prefix existed, return a dummy value */
	if (prefix == NULL)
		return snprintf(buffer, PAGE_SIZE, "<not set>");

	/* Otherwise, return a human-readable version of our copy */
	return snprintf(buffer, PAGE_SIZE, "%x:%x:%x:%x::/64",
			be16_to_cpu(prefix_copy[0]),
			be16_to_cpu(prefix_copy[1]),
			be16_to_cpu(prefix_copy[2]),
			be16_to_cpu(prefix_copy[3]));
}


/* === Functions for managing the list of allowed subnets === */

/* Replace the subnet list, and free the old one when readers have
 * abandoned it.
 */
static void update_subnet_list(const struct ipv4_subnet_list **subnets_ptr,
			       const struct ipv4_subnet_list *new_subnets)
{
	const struct ipv4_subnet_list *old_subnets;

	/* Perform RCU update */
	spin_lock(&param_write_lock);
	old_subnets = *subnets_ptr;
	rcu_assign_pointer(*subnets_ptr, new_subnets);
	spin_unlock(&param_write_lock);

	/* Free the old subnets when ready. */
	synchronize_rcu();
	kfree(old_subnets);
}

/* If the given IPv4 address is contained within one of the subnets, return 0.
 * Otherwise, return a negative.  This is O(n), but the number of subnets
 * is likely to be very small.
 */
static int scan_subnet_list(const struct ipv4_subnet_list **subnets_ptr,
			    __be32 v4addr)
{
	int res = -EPERM;
	const struct ipv4_subnet_list *subnets;
	const struct ipv4_subnet *net;

	rcu_read_lock();
	subnets = rcu_dereference(*subnets_ptr);
	if (subnets != NULL) {
		size_t i;
		for (i = 0; i < subnets->size; i++) {
			net = &subnets->entry[i];
			if ((v4addr & net->mask) == (net->ip & net->mask)) {
				res = 0;
				break;
			}
		}
	}
	rcu_read_unlock();

	return res;
}

#define param_check_subnet_list(name, p) \
	__param_check(name, p, const struct ipv4_subnet_list *)

static int param_set_subnet_list(const char *val, struct kernel_param *kp)
{
	int res;
	struct ipv4_subnet_list *new_subnets = NULL;

	/* Skip leading whitespace. */
	while (isspace(*val))
		val++;

	/* If input is empty, clear the prefix. */
	if (*val == '\0') {
		printk(KERN_INFO "stubl: Clearing subnet list.\n");
		update_subnet_list(kp->arg, NULL);
		return 0;
	}

	res = parse_ipv4_subnet_list(val, &new_subnets);
	if (res < 0) {
		printk(KERN_INFO "stubl: Can't parse subnet list.\n");
		return res;
	}

	printk(KERN_INFO "stubl: Setting subnet list.\n");

	/* Perform RCU update */
	update_subnet_list(kp->arg, new_subnets);
	return 0;
}

static int param_get_subnet_list(char *buffer, struct kernel_param *kp)
{
	const struct ipv4_subnet_list **subnets_ptr = kp->arg;
	const struct ipv4_subnet_list *subnets;
	size_t blen = 0;

	rcu_read_lock();
	subnets = rcu_dereference(*subnets_ptr);
	if (subnets != NULL) {
		size_t i;
		for (i = 0; i < subnets->size; i++) {
			/* Separate entries with spaces. */
			if (i > 0) {
				blen += snprintf(buffer + blen,
						 PAGE_SIZE - blen, " ");
			}

			/* Add a.b.c.d/e string */
			blen += ipv4_subnet_to_string(buffer + blen,
						      PAGE_SIZE - blen,
						      &subnets->entry[i]);
		}
	}
	rcu_read_unlock();

	return blen;
}

module_param(tunnel_key, cipher_key, 0644);
MODULE_PARM_DESC(tunnel_key,
		 "Blowfish key for decrypting IPv6 address suffixes. "
		 "Input must be an even number of hex digits.");

module_param(tunnel_prefix, ipv6_prefix, 0644);
MODULE_PARM_DESC(tunnel_prefix,
		 "IPv6 /64 prefix controlled by this tunnel, formatted "
		 "like 2001:db8:0:1234");

module_param(allowed_subnets, subnet_list, 0644);
MODULE_PARM_DESC(allowed_subnets,
		 "A space-separated list of IPv4 subnets which are allowed to "
		 "be tunnel endpoints, formatted like 192.168.1.0/24.");


/* === Gritty tunnel details, largely based on sit.c === */

static void ipip6_tunnel_uninit(struct net_device *dev)
{
	/* Assume the kernel is sane enough not to give us packets
	 * while we're destructing. */
	tunnels_wc[0] = NULL;
	dev_put(dev);
}

static int ipip6_err(struct sk_buff *skb, u32 info)
{
	/* Yield to the next tunnel. */
	return -ENOENT;
}

static inline void ipip6_ecn_decapsulate(struct iphdr *iph, struct sk_buff *skb)
{
	if (INET_ECN_is_ce(iph->tos))
		IP6_ECN_set_ce(ipv6_hdr(skb));
}

static int extract_ipv4_endpoint(const struct in6_addr *v6addr,
                                 __be32 *v4addr) {
	int err;
	__be32 decrypted_suffix[2];

	/* Only proceed if the IPv6 prefix matches this tunnel's. */
	if (compare_ipv6_prefix(&tunnel_prefix, v6addr) != 0)
		return -ERANGE;

	/* According to RFC2373, the tunnel addresses must have the
	 * universal/local bit set to 0. */
	if (v6addr->s6_addr[8] & 0x02)
		return -EINVAL;

	/* Decrypt the 64-bit suffix.  This fails if tunnel_key has not
 	 * been set. */
	err = try_decrypt64(&tunnel_key,
                            (u8*)decrypted_suffix, &v6addr->s6_addr[8]);
	if (err < 0)
		return err;

	/* A valid decryption should match this pattern:
	 * IPV4:IPV4:0000:00xx
	 *
	 * The last 6 bits are free.  For each IPv4 endpoint, this allows 64
	 * chances to generate an address with the universal/local bit
	 * cleared.  The probability of failure is 1 in 2^64, or
	 * "basically impossible."
	 *
	 * We restrict the number of free bits in order to prevent outsiders
	 * from generating random proto-41 packets to  previously unseen
	 * addresses on the internal IPv4 network.  With 6 bits of free space,
	 * the probability of a random address decrypting to something valid
	 * is 1 in 2^26.  Using iptables to further restrict the incoming
	 * and outgoing proto-41 endpoints is strongly recommended.
	 */
	if (be32_to_cpu(decrypted_suffix[1]) & ~0x3F)
		return -EINVAL;

	/* Extract IPv4 address from first half of decrypted suffix. */
	*v4addr = decrypted_suffix[0];

	/* Check if this IPv4 address is on the list of allowed subnets. */
	err = scan_subnet_list(&allowed_subnets, *v4addr);
	if (err < 0)
		return err;

	return 0;
}

static int check_stubl_source(struct sk_buff *skb)
{
	int err;
	__be32 v4src;
	struct in6_addr *v6src;
	__be32 decrypted_v4addr;

	v4src = ip_hdr(skb)->saddr;
	v6src = &ipipv6_hdr(skb)->saddr;

	err = extract_ipv4_endpoint(v6src, &decrypted_v4addr);
	if (err < 0)
		return err;

	if (decrypted_v4addr != v4src)
		return -EINVAL;

	return 0;
}

static int ipip6_rcv(struct sk_buff *skb)
{
	int err;
	struct iphdr *iph;
	struct ip_tunnel *tunnel = tunnels_wc[0];

	/* Returning nonzero yields to the next tunnel device */

	if (!(tunnel && tunnel->dev->flags&IFF_UP))
		return -1;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return -1;

	err = check_stubl_source(skb);
	if (err == -ERANGE) {
		/* Not my prefix, let the next tunnel handle it. */
		return -1;
	} else if (err < 0) {
		/* For any other errors, send an ICMPv4 reject. */
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		kfree_skb(skb);
		return 0;
	}

	iph = ip_hdr(skb);

	secpath_reset(skb);
	skb->mac_header = skb->network_header;
	skb_reset_network_header(skb);
	IPCB(skb)->flags = 0;
	skb->protocol = htons(ETH_P_IPV6);
	skb->pkt_type = PACKET_HOST;
	tunnel->stat.rx_packets++;
	tunnel->stat.rx_bytes += skb->len;
	skb->dev = tunnel->dev;
	dst_release(skb->dst);
	skb->dst = NULL;
	nf_reset(skb);
	ipip6_ecn_decapsulate(iph, skb);
	netif_rx(skb);
	return 0;
}


/*
 *	This function assumes it is being called from dev_queue_xmit()
 *	and that skb is filled properly by that function.
 */

static int ipip6_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct net_device_stats *stats = &tunnel->stat;
	struct iphdr  *tiph = &tunnel->parms.iph;
	struct ipv6hdr *iph6 = ipv6_hdr(skb);
	u8     tos = tunnel->parms.iph.tos;
	struct rtable *rt;     			/* Route to the other host */
	struct net_device *tdev;			/* Device to other host */
	struct iphdr  *iph;			/* Our new IP header */
	unsigned int max_headroom;		/* The extra header space needed */
	__be32 dst = tiph->daddr;
	int    mtu;

	if (tunnel->recursion++) {
		tunnel->stat.collisions++;
		goto tx_error;
	}

	if (skb->protocol != htons(ETH_P_IPV6))
		goto tx_error;

	if (extract_ipv4_endpoint(&iph6->daddr, &dst) < 0)
		goto tx_error_icmp;

	{
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = dst,
						.saddr = tiph->saddr,
						.tos = RT_TOS(tos) } },
				    .oif = tunnel->parms.link,
				    .proto = IPPROTO_IPV6 };
		if (ip_route_output_key(&rt, &fl)) {
			tunnel->stat.tx_carrier_errors++;
			goto tx_error_icmp;
		}
	}
	if (rt->rt_type != RTN_UNICAST) {
		ip_rt_put(rt);
		tunnel->stat.tx_carrier_errors++;
		goto tx_error_icmp;
	}
	tdev = rt->u.dst.dev;

	if (tdev == dev) {
		ip_rt_put(rt);
		tunnel->stat.collisions++;
		goto tx_error;
	}

	if (tiph->frag_off)
		mtu = dst_mtu(&rt->u.dst) - sizeof(struct iphdr);
	else
		mtu = skb->dst ? dst_mtu(skb->dst) : dev->mtu;

	if (mtu < 68) {
		tunnel->stat.collisions++;
		ip_rt_put(rt);
		goto tx_error;
	}
	if (mtu < IPV6_MIN_MTU)
		mtu = IPV6_MIN_MTU;
	if (tunnel->parms.iph.daddr && skb->dst)
		skb->dst->ops->update_pmtu(skb->dst, mtu);

	if (skb->len > mtu) {
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, dev);
		ip_rt_put(rt);
		goto tx_error;
	}

	if (tunnel->err_count > 0) {
		if (jiffies - tunnel->err_time < IPTUNNEL_ERR_TIMEO) {
			tunnel->err_count--;
			dst_link_failure(skb);
		} else
			tunnel->err_count = 0;
	}

	/*
	 * Okay, now see if we can stuff it in the buffer as-is.
	 */
	max_headroom = LL_RESERVED_SPACE(tdev)+sizeof(struct iphdr);

	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			ip_rt_put(rt);
			stats->tx_dropped++;
			dev_kfree_skb(skb);
			tunnel->recursion--;
			return 0;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
		iph6 = ipv6_hdr(skb);
	}

	skb->transport_header = skb->network_header;
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags = 0;
	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

	/*
	 *	Push down and install the IPIP header.
	 */

	iph 			=	ip_hdr(skb);
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr)>>2;
	if (mtu > IPV6_MIN_MTU)
		iph->frag_off	=	htons(IP_DF);
	else
		iph->frag_off	=	0;

	iph->protocol		=	IPPROTO_IPV6;
	iph->tos		=	INET_ECN_encapsulate(tos, ipv6_get_dsfield(iph6));
	iph->daddr		=	rt->rt_dst;
	iph->saddr		=	rt->rt_src;

	if ((iph->ttl = tiph->ttl) == 0)
		iph->ttl	=	iph6->hop_limit;

	nf_reset(skb);

	IPTUNNEL_XMIT();
	tunnel->recursion--;
	return 0;

tx_error_icmp:
	dst_link_failure(skb);
tx_error:
	stats->tx_errors++;
	dev_kfree_skb(skb);
	tunnel->recursion--;
	return 0;
}

static struct net_device_stats *ipip6_tunnel_get_stats(struct net_device *dev)
{
	return &(((struct ip_tunnel*)netdev_priv(dev))->stat);
}

static int ipip6_tunnel_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < IPV6_MIN_MTU || new_mtu > 0xFFF8 - sizeof(struct iphdr))
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static void ipip6_tunnel_setup(struct net_device *dev)
{
	dev->uninit		= ipip6_tunnel_uninit;
	dev->destructor 	= free_netdev;
	dev->hard_start_xmit	= ipip6_tunnel_xmit;
	dev->get_stats		= ipip6_tunnel_get_stats;
	dev->change_mtu		= ipip6_tunnel_change_mtu;

	/* Set type to NONE rather than SIT, to avoid the magic ::/96 route,
	 * and other possible interference with the real sit module. */
	dev->type		= ARPHRD_NONE;
	dev->hard_header_len 	= LL_MAX_HEADER + sizeof(struct iphdr);
	dev->mtu		= ETH_DATA_LEN - sizeof(struct iphdr);
	dev->flags		= IFF_NOARP;
	dev->iflink		= 0;
	dev->addr_len		= 4;
}

static int __init ipip6_fb_tunnel_init(struct net_device *dev)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct iphdr *iph = &tunnel->parms.iph;

	tunnel->dev = dev;
	strcpy(tunnel->parms.name, dev->name);

	iph->version		= 4;
	iph->protocol		= IPPROTO_IPV6;
	iph->ihl		= 5;
	iph->ttl		= 64;

	dev_hold(dev);
	tunnels_wc[0]		= tunnel;
	return 0;
}

static struct xfrm_tunnel sit_handler = {
	.handler	=	ipip6_rcv,
	.err_handler	=	ipip6_err,

	/* Must have higher priority (lower number) than sit */
	.priority	=	0,
};

static void __exit sit_cleanup(void)
{
	xfrm4_tunnel_deregister(&sit_handler, AF_INET6);

	rtnl_lock();
	unregister_netdevice(ipip6_fb_tunnel_dev);
	rtnl_unlock();

	/* Use RCU for the cleanup, just in case... */
	update_cipher(&tunnel_key, NULL);
	update_ipv6_prefix(&tunnel_prefix, NULL);
	update_subnet_list(&allowed_subnets, NULL);
}

static int __init sit_init(void)
{
	int err;
	printk(KERN_INFO "stubl: IPv6 Stateless Tunnel Broker for LANs\n");

	if (xfrm4_tunnel_register(&sit_handler, AF_INET6) < 0) {
		printk(KERN_INFO "stubl init: Can't add protocol\n");
		return -EAGAIN;
	}

	ipip6_fb_tunnel_dev = alloc_netdev(sizeof(struct ip_tunnel), "stubl0",
					   ipip6_tunnel_setup);
	if (!ipip6_fb_tunnel_dev) {
		err = -ENOMEM;
		goto err1;
	}

	ipip6_fb_tunnel_dev->init = ipip6_fb_tunnel_init;

	if ((err =  register_netdev(ipip6_fb_tunnel_dev)))
		goto err2;

 out:
	return err;
 err2:
	free_netdev(ipip6_fb_tunnel_dev);
 err1:
	xfrm4_tunnel_deregister(&sit_handler, AF_INET6);
	goto out;
}

module_init(sit_init);
module_exit(sit_cleanup);
MODULE_LICENSE("GPL");
MODULE_ALIAS("stubl0");
