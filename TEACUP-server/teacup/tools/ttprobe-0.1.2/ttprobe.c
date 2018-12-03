/*
 * ttprobe v0.1.2 - TEACUP TCP states logger with kprobe.
 *
 * ttprobe was developed by Rasool Al-Saadi <ralsaadi@swin.edu.au>i
 * (Centre for Advanced Internet Architectures,
 * Swinburne University of Technology)
 * and is a modified version of tcpprobe by
 * Stephen Hemminger <shemminger@linux-foundation.org>
 * 
 * The idea for tcpprobe came from Werner Almesberger's umlsim
 *
 * tcpprobe code Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 * ttprobe code Copyright (C) 2017, Rasool Al-Saadi <ralsaadi@swin.edu.au>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <linux/version.h>
#include <asm/uaccess.h>


MODULE_AUTHOR("Rasool Al-Saadi <ralsaadi@swin.edu.au>");
MODULE_DESCRIPTION("TEACUP TCP states logger");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.2");

static int port __read_mostly = 0;
MODULE_PARM_DESC(port, "Port to match (0=all)");
module_param(port, int, 0);

static unsigned int bufsize __read_mostly = 8192;
MODULE_PARM_DESC(bufsize, "Log buffer size in packets (8192)");
module_param(bufsize, uint, 0);

static unsigned int fwmark __read_mostly;
MODULE_PARM_DESC(fwmark, "skb mark to match (0=no mark)");
module_param(fwmark, uint, 0);

static int full __read_mostly = 1;
MODULE_PARM_DESC(full, "Full log (1=every packet received/sent,  0=only cwnd changes)");
module_param(full, int, 0);

static int omode __read_mostly = 0;
MODULE_PARM_DESC(omode, "omode (0=ttprobe, 1=binary, 2=web10g)");
module_param(omode, int, 0);

static int direction __read_mostly = 2;
MODULE_PARM_DESC(direction, "direction (0=snd, 1=rcv, 2=both)");
module_param(direction, int, 0);


static const char procname[] = "ttprobe";

struct tcp_log {
	struct timeval tv;
	union {
		u8     v4[4];
	        u16    v6[8];
	} src_addr, dst_addr;
        u16     src_port;
        u16     dst_port;

	u16	length;
	u32	snd_nxt;
	u32	snd_una;
	u32	snd_wnd;
	u32	rcv_wnd;
	u32	snd_cwnd;
	u32	ssthresh;
	u32	srtt;
	u32     mss_cache;
	u8 	sock_state;
	u8 	direction;
	u8	addr_family;

};

static struct {
	spinlock_t	lock;
	wait_queue_head_t wait;
	ktime_t		start;
	u32		lastcwnd;
	u8		flush;
	u8		finish;
	u32		pktcounter;
	u32		dropedpkts;

	unsigned long	head, tail;
	struct tcp_log	*log;
} tcp_probe;


static inline int tcp_probe_used(void)
{
	return (tcp_probe.head - tcp_probe.tail) & (bufsize - 1);
}

static inline int tcp_probe_avail(void)
{
	return bufsize - tcp_probe_used() - 1;
}


static inline int jtcp_packet_handler(struct sock *sk, struct sk_buff *skb,char direction)
{
		const struct tcp_sock *tp = tcp_sk(sk);
		const struct inet_sock *inet = inet_sk(sk);

		/* Only update if port or skb mark matches */
		if (((port == 0 && fwmark == 0) ||
			 ntohs(inet->inet_dport) == port ||
			 ntohs(inet->inet_sport) == port ||
			 (fwmark > 0 && skb->mark == fwmark)) &&
			(full || tp->snd_cwnd != tcp_probe.lastcwnd)) {

				spin_lock(&tcp_probe.lock);
				/* If log fills, just silently drop */
				if (tcp_probe_avail() > 1) {
						struct tcp_log *p = tcp_probe.log + tcp_probe.head;
						/* get current datetime */
						do_gettimeofday(&p->tv);
						p->addr_family = sk->sk_family;
						switch (sk->sk_family) {
						case AF_INET:
				memcpy(&p->src_addr.v4, &inet->inet_saddr, sizeof(inet->inet_saddr));
				p->src_port = inet->inet_sport;
				memcpy(&p->dst_addr.v4, &inet->inet_daddr, sizeof(inet->inet_daddr));
								p->dst_port = inet->inet_dport;
								break;

						case AF_INET6:
#if IS_ENABLED(CONFIG_IPV6)
							memcpy(&p->src_addr.v6, &inet6_sk(sk)->saddr, sizeof( inet6_sk(sk)->saddr));
							p->src_port = inet->inet_sport;
							memcpy(&p->dst_addr.v6, &sk->sk_v6_daddr, sizeof(sk->sk_v6_daddr));
							p->dst_port = inet->inet_dport;

#endif
							break;

						default:
								BUG();
						}

						p->length = skb->len;
						p->snd_nxt = tp->snd_nxt;
						p->snd_una = tp->snd_una;
						p->snd_cwnd = tp->snd_cwnd;
						p->snd_wnd = tp->snd_wnd;
						p->rcv_wnd = tp->rcv_wnd;
						p->ssthresh = tcp_current_ssthresh(sk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
						p->srtt = tp->srtt >> 3;
#else
						p->srtt = tp->srtt_us >> 3;
#endif
						p->mss_cache = tp->mss_cache;
						p->sock_state = sk->sk_state;
						p->direction = direction;

						tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
				}
				else
						tcp_probe.dropedpkts++;
				tcp_probe.lastcwnd = tp->snd_cwnd;
				spin_unlock(&tcp_probe.lock);

				wake_up(&tcp_probe.wait);
		}
		
		return 0;

}

/*
 * Hook inserted to be called before each send packet.
 * Note: arguments must match tcp_transmit_skb()!
*/ 
static int jtcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,gfp_t gfp_mask)
{
	jtcp_packet_handler(sk, skb,'o');
	jprobe_return();
	return 0;
}


/*
 * Hook inserted to be called before each TCP_v4
 * receive packet. Note: arguments must match
 * tcp_v4_do_rcv()
 */
static int jtcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	jtcp_packet_handler(sk, skb,'i');
	jprobe_return();
	return 0;
}


/*
 * Hook inserted to be called before each TCP_v6
 * receive packet. Note: arguments must match
 * tcp_v6_do_rcv()
 */
static int jtcp_v6_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	jtcp_packet_handler(sk, skb,'i');
	jprobe_return();
	return 0;
}


static struct jprobe tcp_jprobe_rcv_v4 = {
	.kp = {
		.symbol_name	= "tcp_v4_do_rcv",
	},
	.entry	= jtcp_v4_do_rcv,
};

#if IS_ENABLED(CONFIG_IPV6)
static struct jprobe tcp_jprobe_rcv_v6 = {
	.kp = {
			.symbol_name    = "tcp_v6_do_rcv",
	},
	.entry  = jtcp_v6_do_rcv,
};
#endif

static struct jprobe tcp_jprobe_snd = {
	.kp = {
			.symbol_name    = "tcp_transmit_skb",
	},
	.entry  = jtcp_transmit_skb,
};


static int tcpprobe_open(struct inode *inode, struct file *file)
{
	/* Reset (empty) log */
	spin_lock_bh(&tcp_probe.lock);
	tcp_probe.head = tcp_probe.tail = 0;
	tcp_probe.start = ktime_get();
	spin_unlock_bh(&tcp_probe.lock);

	return 0;
}

/* create a formated IPv6 address from an array */
static inline void arraytoipv6(const u16 *addr, char *tbuf, int n)
{
 scnprintf(tbuf, 200,"%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
 	ntohs(addr[0]), ntohs(addr[1]), ntohs(addr[2]),
	ntohs(addr[3]), ntohs(addr[4]), ntohs(addr[5]),
	ntohs(addr[6]), ntohs(addr[7]));
}

/* create a formated IPv4 address from an array */
static inline void arraytoipv4(const u8 *addr, char *tbuf, int n)
{
 scnprintf(tbuf, 200,"%u.%u.%u.%u",
 	addr[0], addr[1], addr[2], addr[3]);

}


static inline int tcpprobe_sprint(char *tbuf, int n)
{
	char tbuf_saddr[42];
	char tbuf_daddr[42];
	const struct tcp_log *p
		= tcp_probe.log + tcp_probe.tail;
	int c = 0;

	switch (omode){
	   case 0: /* ttprobe format */
		if (p->addr_family == AF_INET)
		{
				arraytoipv4(p->src_addr.v4, tbuf_saddr, 42);
				arraytoipv4(p->dst_addr.v4, tbuf_daddr, 42);

		}
		else if (p->addr_family == AF_INET6){
			arraytoipv6(p->src_addr.v6, tbuf_saddr, 42);
			arraytoipv6(p->dst_addr.v6, tbuf_daddr, 42);
		}

				c = scnprintf(tbuf, n,
				  "%c,%ld.%06ld,%s,%u,%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
				p->direction,
				(long int) p->tv.tv_sec,(long int)p->tv.tv_usec,
				tbuf_saddr,
				ntohs(p->src_port), 

				tbuf_daddr, 
				ntohs(p->dst_port), 

				tcp_probe.pktcounter,
				p->mss_cache,
				p->srtt,
				p->snd_cwnd * p->mss_cache, /*10*/
				p->ssthresh * p->mss_cache, /*11*/
				p->snd_wnd, /*12*/
				p->rcv_wnd, /*13*/
				p->sock_state,
				p->snd_una,
				p->snd_nxt,
		p->length 

				);
		break;
	   case 1: /* binary format */
			memcpy(tbuf,p,sizeof(struct tcp_log));
			c = sizeof(struct tcp_log);
			break;
	   case 2: /* web10g format */
			   if (p->addr_family == AF_INET)
				{
						arraytoipv4(p->src_addr.v4, tbuf_saddr, 42);
						arraytoipv4(p->dst_addr.v4, tbuf_daddr, 42);

				}
				else if (p->addr_family == AF_INET6){
						arraytoipv6(p->src_addr.v6, tbuf_saddr, 42);
						arraytoipv6(p->dst_addr.v6, tbuf_daddr, 42);
				}

				c = scnprintf(tbuf, n,
								"%ld.%06ld,,%s,%u,%s,%u,%u,,,,,,,,,,,,,%u,,,%u,,,%u,%u,,%u,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,%u,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,%u,%u\n",
				(long int) p->tv.tv_sec,(long int)p->tv.tv_usec, /* 1*/
				tbuf_saddr, /*3*/
				ntohs(p->src_port), /*4*/

				tbuf_daddr, /*5*/
				ntohs(p->dst_port), /*6*/

				tcp_probe.pktcounter, /*7 - wrong value - */
				p->mss_cache, /*20*/
				p->srtt / 1000, /*23*/
				p->snd_cwnd * p->mss_cache , /*26*/
				p->ssthresh * p->mss_cache, /*27*/
				p->rcv_wnd, /*29*/
				p->sock_state, /*76*/
				p->snd_una, /*108*/
				p->snd_nxt /*109*/

				);
				/*
				p->length,
				*/
				break;

	}
	return c;
}

static ssize_t tcpprobe_read(struct file *file, char __user *buf,
			     size_t len, loff_t *ppos)
{
	size_t cnt=0;
	int error = 0;
	if (!buf)
		return -EINVAL;

	while (cnt < len) {
		char tbuf[1024];
		int width;

		/* Wait for data in buffer, flush the buffer,
		 * or finish logging*/
		error = wait_event_interruptible(tcp_probe.wait,
			tcp_probe_used() > 0 ||  tcp_probe.flush 
			|| tcp_probe.finish);
		if (tcp_probe.finish) {
			tcp_probe.finish = 0;
			return 0;
		}
		if (tcp_probe_used()<=0 && tcp_probe.flush){
			if (cnt == 0){
				/* if no items in buffer and user
				 * requests flush, then reset flush
				 *  flage and continue */
				tcp_probe.flush = 0;
				continue;
			}
			else
				break;
		}

		if (error)
			break;
		spin_lock_bh(&tcp_probe.lock);
		if (tcp_probe.head == tcp_probe.tail) {
			/* multiple readers race? */
			spin_unlock_bh(&tcp_probe.lock);
			continue;
		}

		width = tcpprobe_sprint(tbuf, sizeof(tbuf));
		tcp_probe.pktcounter++;

		if (cnt + width < len)
			tcp_probe.tail = (tcp_probe.tail + 1) & (bufsize - 1);

		spin_unlock_bh(&tcp_probe.lock);

		/* if record greater than space available
		   return partial buffer (so far) */
		if (cnt + width >= len)
			break;
		if (copy_to_user(buf + cnt, tbuf, width))
			return -EFAULT;
		cnt += width;
	}
	/* reset flush flage if all items are written to user buffer */
	if(tcp_probe.flush == 1 && cnt < len ){
		tcp_probe.flush=0;

	}
	return cnt == 0 ? error : cnt;
}


static ssize_t tcpprobe_write (struct file *file, const char *buf,
	size_t count, loff_t *off)
{
	char buffer[256];
	size_t inbufcount = 256;
	int bwritten = 0;

	if (count < inbufcount)
		inbufcount = count;
	bwritten = copy_from_user(buffer, buf, inbufcount);
	buffer[inbufcount-1] = 0;
	if (!strcmp(buffer,"flush")){		
		pr_info("ttprobe - flushing the buffer\n");
		pr_info("ttprobe - droped pkts = %u\n", tcp_probe.dropedpkts);
		tcp_probe.flush = 1;
		wake_up(&tcp_probe.wait);
	}
		else if (!strcmp(buffer, "finish")){
				pr_info("ttprobe - send EOF to userspace\n");
				tcp_probe.finish = 1;
				wake_up(&tcp_probe.wait);
		}

	return count;
}

static const struct file_operations tcpprobe_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tcpprobe_open,
	.read    = tcpprobe_read,
	.write	 = tcpprobe_write,
	.llseek  = noop_llseek,
};

static __init int tcpprobe_init(void)
{
	int ret = -ENOMEM;

	/* Warning: if the function signature of tcp_v4_do_rcv,
	 * tcp_v6_do_rcv or tcp_transmit_skb have been changed,
	 * you also have to change the signature of
	 * jtcp_v4_do_rcv, jtcp_v6_do_rcv and jtcp_transmit_skb 
	 * otherwise you end up right here!
	 */

	BUILD_BUG_ON(__same_type(tcp_v4_do_rcv,
				 jtcp_v4_do_rcv) == 0);
/*
        BUILD_BUG_ON(__same_type(tcp_v6_do_rcv,
                                 jtcp_v6_do_rcv) == 0);
        BUILD_BUG_ON(__same_type(tcp_transmit_skb,
                                 jtcp_transmit_skb) == 0);
*/
	init_waitqueue_head(&tcp_probe.wait);
	spin_lock_init(&tcp_probe.lock);

	if (bufsize == 0)
		return -EINVAL;

	tcp_probe.flush = 0;
	tcp_probe.pktcounter = 0;
	tcp_probe.dropedpkts = 0;
	tcp_probe.finish = 0;
	bufsize = roundup_pow_of_two(bufsize);
	tcp_probe.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
	if (!tcp_probe.log)
		goto err0;

	if (!proc_create(procname, S_IRUSR, init_net.proc_net, &tcpprobe_fops))
		goto err0;

	if (direction == 1 || direction == 2){
		ret = register_jprobe(&tcp_jprobe_rcv_v4);
		if (ret)
			goto err1;
#if IS_ENABLED(CONFIG_IPV6)
		ret = register_jprobe(&tcp_jprobe_rcv_v6);
                if (ret)
                        goto err1;
#endif
	}
       if (direction == 0 || direction == 2){
		ret = register_jprobe(&tcp_jprobe_snd);
        	if (ret)
                	goto err1;
	}

	pr_info("ttprobe registered (port=%d/fwmark=%u) bufsize=%u\n",
		port, fwmark, bufsize);
	return 0;
 err1:
	remove_proc_entry(procname, init_net.proc_net);
 err0:
	kfree(tcp_probe.log);
	return ret;
}
module_init(tcpprobe_init);

static __exit void tcpprobe_exit(void)
{
	tcp_probe.finish = 1;
	remove_proc_entry(procname, init_net.proc_net);
        if (direction == 1 || direction == 2){
		unregister_jprobe(&tcp_jprobe_rcv_v4);
#if IS_ENABLED(CONFIG_IPV6)
		unregister_jprobe(&tcp_jprobe_rcv_v6);
#endif
	}
        if (direction == 0 || direction == 2)
		unregister_jprobe(&tcp_jprobe_snd);

	kfree(tcp_probe.log);
}
module_exit(tcpprobe_exit);
