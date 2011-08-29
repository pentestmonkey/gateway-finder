The homepage for this project is:
http://pentestmonkey.net/tools/gateway-finder

Gateway-finder is a scapy script that will help you determine which of the systems on the local LAN has IP forwarding enabled and which can reach the Internet.

This can be useful during Internal pentests when you want to quickly check for unauthorised routes to the Internet (e.g. rogue wireless access points) or routes to other Internal LANs.  It doesn't perform a hugely thorough check, but it is quick at least.  It's python, so it should be easy to modify to fit your needs.

[ Overview ]

You give the script the IP address of a system on the Internet you're trying to reach and it will send the following probes via each system on the local LAN:

* An ICMP Ping
* A TCP SYN packet to port 80
* An ICMP Ping with a TTL of 1
* A TCP SYN packet to port 80 with a TTL of 1

It will report separately which systems send an ICMP "TTL exceeded in transit" message back (indicating that they're routers) and which respond to the probe (indicating that they're gateways to the Internet).

[ Dependencies ]

Python and Scapy.  On Debian / Ubuntu you should just need to do this:

# apt-get install python-scapy

[ Usage ]

# python gateway-finder.py -h
WARNING: No route found for IPv6 destination :: (no default route?)
Usage: gateway-finder.py [ -I interface ] -i ip -f macs.txt

Tries to find a layer-3 gateway to the Internet.  Attempts to reach an IP
address using ICMP ping and TCP SYN to port 80 via each potential gateway
in macs.txt (ARP scan to find MACs)

Options:
  -h, --help            show this help message and exit
  -i IP, --ip=IP        Internet IP to probe
  -v, --verbose         Verbose output
  -I INTERFACE, --interface=INTERFACE
                        Network interface to use
  -f MACFILE, --macfil=MACFILE
                        File containing MAC addresses

[ Step 1: Run an ARP scan to identify systems on the local LAN ]

Use your favourite ARP scanning to identify systems on the local LAN. Save the output (I use to arp.txt in the example below).

# arp-scan -l | tee arp.txt
Interface: eth0, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.6 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
10.0.0.100     00:13:72:09:ad:76       Dell Inc.
10.0.0.200     00:90:27:43:c0:57       INTEL CORPORATION
10.0.0.254     00:08:74:c0:40:ce       Dell Computer Corp.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.6: 256 hosts scanned in 2.099 seconds (121.96 hosts/sec).  3 responded

[ Step 2: Run gateway-finder on the list of local systems ]

Gateway-finder needs two bits of input from you:
* The MAC addresses of the potential gateways
* The IP address of a system on the Internet (I use a google.com address in the example below):

If arp.txt also contains an IP of each system on the same line as the MAC, you'll get much nicer output.  If you need to use a different network interfaces, use the -I option.

# python gateway-finder.py -f arp.txt -i 209.85.227.99
gateway-finder v1.0 http://pentestmonkey.net/tools/gateway-finder

[+] Using interface eth0 (-I to change)
[+] Found 3 MAC addresses in arp.txt
[+] 00:13:72:09:AD:76 [10.0.0.100] appears to route ICMP Ping packets to 209.85.227.99.  Received ICMP TTL Exceeded in transit response.
[+] 00:13:72:09:AD:76 [10.0.0.100] appears to route TCP packets 209.85.227.99:80.  Received ICMP TTL Exceeded in transit response.
[+] We can ping 209.85.227.99 via 00:13:72:09:AD:76 [10.0.0.100]
[+] We can reach TCP port 80 on 209.85.227.99 via 00:13:72:09:AD:76 [10.0.0.100]
[+] Done

