#!/usr/local/bin/python
# Copyright (c) 2013-2017 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Sebastian Zander (szander@swin.edu.au)(2015)
# Tweaks: Grenville Armitage (garmitage@swin.edu.au)(2017)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Detect packet loss between a source and destination 
# The tool computes hashes over the payloads of all packets seen at both
# ends, i.e. source and destination. Then it checks which hashes are seen 
# at the source, but not the destination. These are the lost packets.
#
# The tool actually outputs a list of timestamps and 0/1, where a 0 means
# a packet was NOT lost and a 1 means a packet was lost, with one entry for 
# each packet that was sent by the sender/source.
#
# $Id: pktloss.py 1413 2017-02-07 03:08:09Z cvsup $

import os
import sys
import dpkt
import getopt
import zlib
import gzip
import socket
import operator


def usage():
    print "Usage: " + os.path.basename(sys.argv[0]) + " -t <trace1> -T <trace2> [-f <filter> [-h] [-v]\n" + \
                "\t-t <trace1> \t\ttcpdump file collected at sender/source\n" + \
                "\t-T <trace2> \t\ttcpdump file collected at receiver/sink\n" + \
                "\t-f <filter> \t\tFlow filter string of form <src_ip>:<src_port>:<dst_ip>:<dst_port>\n" + \
                "\t-h \t\t\tshow usage\n" + \
                "\t-v \t\t\tenable verbose mode"


def die(msg, show_usage=False):
    print msg
    if show_usage:
        usage()
    sys.exit(1)

# main

verbose = False
filter_string = ''
trace1_fname = ''
trace2_fname = ''

try:
    opts, args = getopt.getopt(sys.argv[1:], "f:t:T:hv")
except getopt.GetoptError, err:
    usage()
    die("Error: " + err.msg)

for o, a in opts:
    if o == "-h":
        usage()
        sys.exit(0)
    elif o == "-f":
        filter_string = a            
    elif o == "-t":
        trace1_fname = a
    elif o == "-T":
        trace2_fname = a
    elif o == "-v":
        verbose = True
    else:
        assert False, "unhandled option " + str(o)


if trace1_fname == '' or trace2_fname == '':
    die('Must specify two tcpdump file names', True)

if trace1_fname.endswith('.gz'):
    f1 = gzip.open(trace1_fname)
else:
    f1 = open(trace1_fname)
pc1 = dpkt.pcap.Reader(f1)
pc1.setfilter(filter_string)

if trace2_fname.endswith('.gz'):
    f2 = gzip.open(trace2_fname)
else:
    f2 = open(trace2_fname)
pc2 = dpkt.pcap.Reader(f2)
pc2.setfilter(filter_string)

h1 = {}
h2 = {}

def get_pkt_hashes(pcap, name, filter_string):
    h = {}

    (filter_sip, 
     filter_sport,
     filter_dip,
     filter_dport) = filter_string.split(':')
    filter_sport = int(filter_sport)
    filter_dport = int(filter_dport)

    cnt = 0
    cnt_t = 0
    cnt_u = 0
    for ts, pkt in pcap:
        # get pointer to ethernet layer and check that we have IP
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        # get pointer to IP layer
        ip = eth.data

        # ignore if src or dst IP not the ones specified in filter
        if socket.inet_ntoa(ip.src) != filter_sip or \
           socket.inet_ntoa(ip.dst) != filter_dip:
	    continue

        # ignore if UDP/TCP src or dst ports not the ones specified in filter
        # get pointer to payload
        if type(ip.data) == dpkt.udp.UDP:
            udp = ip.data
            if udp.sport != filter_sport or udp.dport != filter_dport:
                continue
            #payload = udp.data
            # Add IP ID field to the string to ensure
            # at least something semi-unique is hashed if UDP payload is invariant
            payload = str(ip.id) +udp.data
            cnt_t += 1
        elif type(ip.data) == dpkt.tcp.TCP:
            tcp = ip.data
            if tcp.sport != filter_sport or tcp.dport != filter_dport:
                continue
            #payload = tcp.data
            # Add IP ID field and TCP Sequence number to the string to ensure
            # at least something semi-unique is hashed if TCP payload is invariant
            payload = str(ip.id) + str(tcp.seq) + tcp.data
            cnt_t += 1
        else:
            continue

        # compute CRC32 and store in dictionary
        phash = zlib.crc32(payload) 
        h[phash] = ts

        cnt += 1

    if verbose:
        print('# Total filtered packets in %s: %i' % (name, cnt))
        print('# Total filtered UDP packets in %s: %i' % (name, cnt_u))
        print('# Total filtered TCP packets in %s: %i' % (name, cnt_t))

    return h


h1 = get_pkt_hashes(pc1, trace1_fname, filter_string)
h2 = get_pkt_hashes(pc2, trace2_fname, filter_string)

f1.close()
f2.close()

# print timestamp, 0/1 (0=arrived, 1=lost) for all packets
# sorted by timestamp
for i in sorted(h1.items(), key=operator.itemgetter(1)):
    if i[0] in h2:
        print('%f 0' % (i[1]))
    else:
        print('%f 1' % (i[1]))

