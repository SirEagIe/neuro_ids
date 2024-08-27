from scapy.all import sniff, TCP, UDP, ICMP, IP


def packet_parse(pkt):
    print(pkt)
    print(type(pkt))
    print(pkt.haslayer(TCP))
    if pkt.haslayer(TCP):
        print('!!!', pkt[IP].flags)


packets = sniff(count=5, prn=packet_parse)
packets = sniff(count=50, prn=lambda x: x.show())
