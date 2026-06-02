from scapy.all import *

def analyze(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "Unknown"

    if packet.haslayer(TCP):
        protocol = "TCP"

    elif packet.haslayer(UDP):
        protocol = "UDP"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    print("\n" + "=" * 60)
    print(f"Source      : {src_ip}")
    print(f"Destination : {dst_ip}")
    print(f"Protocol    : {protocol}")

    if packet.haslayer(TCP):

        print(f"Source Port : {packet[TCP].sport}")
        print(f"Dest Port   : {packet[TCP].dport}")

    elif packet.haslayer(UDP):

        print(f"Source Port : {packet[UDP].sport}")
        print(f"Dest Port   : {packet[UDP].dport}")

    if packet.haslayer(Raw):

        try:
            payload = packet[Raw].load.decode(
                errors="ignore"
            )

            print("\nPayload:")
            print(payload[:300])

        except:
            pass

sniff(prn=analyze, store=False)
