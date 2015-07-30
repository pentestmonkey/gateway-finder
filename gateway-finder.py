#!/usr/bin/env python
# gateway-finder - Tool to identify routers on the local LAN and paths to the Internet
# Copyright (C) 2011 pentestmonkey@pentestmonkey.net
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as 
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  If these terms are not acceptable to 
# you, then do not use this tool.
# 
# You are encouraged to send comments, improvements or suggestions to
# me at pentestmonkey at pentestmonkey.net
#

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import os
from time import sleep
import signal
from optparse import OptionParser

parser = OptionParser(usage="Usage: %prog [ -I interface ] -i ip -f macs.txt\n\nTries to find a layer-3 gateway to the Internet.  Attempts to reach an IP\naddress using ICMP ping and TCP SYN to port 80 via each potential gateway\nin macs.txt (ARP scan to find MACs)")
parser.add_option("-i", "--ip", dest="ip", help="Internet IP to probe")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output")
parser.add_option("-I", "--interface", dest="interface", default="eth0", help="Network interface to use")
parser.add_option("-f", "--macfil", dest="macfile", help="File containing MAC addresses")

(options, args) = parser.parse_args()

if not options.macfile:
	print "[E] No macs.txt specified.  -h for help."
	sys.exit(0)

if not options.ip:
	print "[E] No target IP specified.  -h for help."
	sys.exit(0)

version = "1.1"
print "gateway-finder v%s http://pentestmonkey.net/tools/gateway-finder" % version
print
print "[+] Using interface %s (-I to change)" % options.interface
macfh = open(options.macfile, 'r')
lines = map(lambda x: x.rstrip(), macfh.readlines())
macs = []
ipofmac = {}
for line in lines:
	m = re.search('([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
	if m and m.group(1):
		ipofmac[m.group(1).upper()] = "UnknownIP"
		m = re.search('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})', line)
		if m and m.group(1) and m.group(2):
			ipofmac[m.group(2).upper()] = m.group(1)
		else:
			m = re.search('([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
			if m and m.group(1) and m.group(2):
				ipofmac[m.group(1).upper()] = m.group(2)

macs = ipofmac.keys()

print "[+] Found %s MAC addresses in %s" % (len(macs), options.macfile)

if len(macs) == 0:
	print "[E] No MAC addresses found in %s" % options.macfile
	sys.exit(0)

def handler(signum, frame):
	vprint("Child process received signal %s.  Exiting." % signum)
	sys.exit(0)

def vprint(message):
	if options.verbose:
		print "[-] %s" % message

signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

def processreply(p):
	# This might error if the packet isn't what we're expecting
	try:
		if p[IP].proto == 1: # ICMP
			if p[ICMP].type == 11 and p[ICMP].code == 0:
				if p[IPerror].proto == 1: # response to ICMP packet
					seq = p[ICMP][ICMPerror].seq
					vprint("Received reply: %s" % p.summary())
					print "[+] %s" % packets[seq]['message']
				if p[IPerror].proto == 6: # response to TCP packet
					seq = p[ICMP][TCPerror].seq
					vprint("Received reply: %s" % p.summary())
					print "[+] %s" % packets[seq]['message']
			else:
				seq = p[ICMP].seq
				vprint("Received reply: %s" % p.summary())
				print "[+] %s" % packets[seq]['message']
		if p[IP].proto == 6: # TCP
			if p[IP].src == options.ip and p[TCP].sport == 80:
				seq = p[TCP].ack - 1 # remote end increments our seq by 1
				vprint("Received reply: %s" % p.summary())
				print "[+] %s" % packets[seq]['message']
	except:
		print "[E] Received unexpected packet.  Ignoring."
	return False

# Build list of packets to send
seq = 0
packets = []
for mac in macs:
	# Echo request, TTL=1
	packets.append({ 'packet': Ether(dst=mac)/IP(dst=options.ip,ttl=1)/ICMP(seq=seq),'type': 'ping', 'dstip': options.ip, 'dstmac': mac, 'seq': seq, 'message': '%s [%s] appears to route ICMP Ping packets to %s.  Received ICMP TTL Exceeded in transit response.' % (mac, ipofmac[mac], options.ip) })
	seq = seq + 1

	# TCP SYN to port 80, TTL=1
	packets.append({ 'packet': Ether(dst=mac)/IP(dst=options.ip,ttl=1)/TCP(seq=seq), 'type': 'tcpsyn', 'dstip': options.ip, 'dstmac': mac, 'seq': seq, 'message': '%s [%s] appears to route TCP packets %s:80.  Received ICMP TTL Exceeded in transit response.' % (mac, ipofmac[mac], options.ip) })
	seq = seq + 1

	# Echo request
	packets.append({ 'packet': Ether(dst=mac)/IP(dst=options.ip)/ICMP(seq=seq),'type': 'ping', 'dstip': options.ip, 'dstmac': mac, 'seq': seq, 'message': 'We can ping %s via %s [%s]' % (options.ip, mac, ipofmac[mac]) })
	seq = seq + 1

	# TCP SYN to port 80
	packets.append({ 'packet': Ether(dst=mac)/IP(dst=options.ip)/TCP(seq=seq), 'type': 'tcpsyn', 'dstip': options.ip, 'dstmac': mac, 'seq': seq, 'message': 'We can reach TCP port 80 on %s via %s [%s]' % (options.ip, mac, ipofmac[mac]) })
	seq = seq + 1

pid = os.fork()
if pid:
	# parent will send packets
	sleep(2) # give child time to start sniffer
	vprint("Parent processing sending packets...")
	for packet in packets:
		sendp(packet['packet'], verbose=0)
	vprint("Parent finished sending packets")
	sleep(2) # give child time to capture last reply
	vprint("Parent killing sniffer process")
	os.kill(pid, signal.SIGTERM)
	vprint("Parent reaping sniffer process")
	os.wait()
	vprint("Parent exiting")

	print "[+] Done"
	print
	sys.exit(0)
	
else:
	# child will sniff
	filter="ip and not arp and ((icmp and icmp[0] = 11 and icmp[1] = 0) or (src host %s and (icmp or (tcp and port 80))))" % options.ip
	vprint("Child process sniffing on %s with filter '%s'" % (options.interface, filter))
	sniff(iface=options.interface, store = 0, filter=filter, prn=None, lfilter=lambda x: processreply(x))
