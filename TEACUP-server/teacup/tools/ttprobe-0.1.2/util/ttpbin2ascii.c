/*
 *
 * ttpb2ascii: ttprobe binary to ASCII converter
 * 
 * This tool is used to convert ttprobe logger binary output to 
 * readable ASCII text. 
 *
 * Copyright (c) 2015, Centre for Advanced Internet Architectures, 
 * Swinburne University of Technology. All rights reserved.
 *
 * Author: Rasool Al-Saadi (ralsaadi@swin.edu.au)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>


typedef unsigned  char          u8;
typedef unsigned short          u16;
typedef unsigned int            u32;
typedef unsigned long long      u64;
typedef signed char             s8;
typedef short                   s16;
typedef int                     s32;
typedef long long               s64;

struct tcp_log {
        struct timeval tv;
        union {
                u8     v4[4];
                u16    v6[8];
        } src_addr, dst_addr;
        u16     src_port;
        u16     dst_port;

        u16     length;
        u32     snd_nxt;
        u32     snd_una;
        u32     snd_wnd;
        u32     rcv_wnd;
        u32     snd_cwnd;
        u32     ssthresh;
        u32     srtt;
        u32     mss_cache;
        u8      sock_state;
        u8      direction;
        u8      addr_family;

};

/* create a formated IPv6 address from an array */
static inline void arraytoipv6(const u16 *addr, char *tbuf, int n)
{
 sprintf(tbuf, "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
         ntohs(addr[0]), ntohs(addr[1]), ntohs(addr[2]),
         ntohs(addr[3]), ntohs(addr[4]), ntohs(addr[5]),
         ntohs(addr[6]), ntohs(addr[7]));
}

/* create a formated IPv4 address from an array */
static inline void arraytoipv4(const u8 *addr, char *tbuf, int n)
{
 sprintf(tbuf, "%u.%u.%u.%u",
        addr[0], addr[1], addr[2], addr[3]);

}


static int tcpprobe_sprint(struct tcp_log *p,char *tbuf, int pktcounter,
		u8 addr_family)
{
     	      char tbuf_saddr[42];
              char tbuf_daddr[42];

               if (p->addr_family == 2){ /* AF_INET */
                        arraytoipv4(p->src_addr.v4, tbuf_saddr, 42);
                        arraytoipv4(p->dst_addr.v4, tbuf_daddr, 42);

                }
                else if (p->addr_family == 10){ /* AF_INET6 */
                        arraytoipv6(p->src_addr.v6, tbuf_saddr, 42);
                        arraytoipv6(p->dst_addr.v6, tbuf_daddr, 42);
                }

                return sprintf(tbuf,
                  "%c,%ld.%06ld,%s,%u,%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
                p->direction,
                (long int) p->tv.tv_sec,(long int)p->tv.tv_usec,
                tbuf_saddr,
                ntohs(p->src_port),

                tbuf_daddr,
                ntohs(p->dst_port),

                pktcounter,
                p->mss_cache,
                p->srtt / 1000,
                p->snd_cwnd * p->mss_cache, /*10*/
                p->ssthresh, /*11*/
                p->snd_wnd  * p->mss_cache, /*12*/
                p->rcv_wnd  * p->mss_cache, /*13*/
                p->sock_state,
                p->snd_una,
                p->snd_nxt,
                p->length

                );

}

int main(int argc, char *argv[])
{
 	       
	char *buffer;
        int count,pktcounter=0;
        struct tcp_log itcp_log;
        buffer = malloc(sizeof(1024));
        while((count = fread(&itcp_log,sizeof(itcp_log),1,stdin))){
              if(count == 1){
                        count = tcpprobe_sprint(&itcp_log,buffer,pktcounter,
				 itcp_log.addr_family);
                        pktcounter++;
                        fwrite(buffer,1,count,stdout);
                }
        }
        return 0;
}

