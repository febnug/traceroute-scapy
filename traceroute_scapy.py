#!/usr/bin/env python3
"""
traceroute_scapy.py
Requires: scapy (pip install scapy) and root privileges.
Usage: sudo python3 traceroute_scapy.py example.com [max_hops]
"""
import sys
from scapy.all import IP, UDP, ICMP, sr1, conf
import socket
import time

conf.verb = 0  # no Scapy verbose

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        raise SystemExit(f"Cannot resolve {host}: {e}")

def traceroute(host, max_hops=30, dport=33434, timeout=2):
    ip = resolve(host)
    print(f"Tracing route to {host} [{ip}], max hops {max_hops}")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=ip, ttl=ttl) / UDP(dport=dport)
        start = time.time()
        reply = sr1(pkt, timeout=timeout)
        rtt = None
        if reply is not None:
            rtt = (time.time() - start) * 1000.0
            src = reply.src
            # if we get ICMP port unreachable from destination, it's the final hop
            if reply.haslayer(ICMP):
                icmp = reply.getlayer(ICMP)
                typ = icmp.type
                code = icmp.code
                print(f"{ttl:2d}  {src:15s}  {rtt:6.2f} ms  (ICMP type={typ} code={code})")
                if typ == 3:  # Destination Unreachable => likely reached target port
                    print("Reached destination (ICMP Destination Unreachable).")
                    break
                else:
                    # TTL exceeded
                    continue
            else:
                print(f"{ttl:2d}  {src:15s}  {rtt:6.2f} ms")
                if src == ip:
                    print("Reached destination (same IP).")
                    break
        else:
            print(f"{ttl:2d}  *")
    print("Done.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 traceroute_scapy.py hostname [max_hops]")
        sys.exit(1)
    target = sys.argv[1]
    maxh = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    traceroute(target, maxh)
