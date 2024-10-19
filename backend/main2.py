import os
from scapy.all import sniff, Ether, IP, TCP, UDP
from connection import Connection


def sniff_flows():
    connections = {}
    def packet_process(pkt):
        print(len(connections.keys()))
        if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            is_forward = int(pkt[IP].src.replace('.', '')) < int(pkt[IP].dst.replace('.', ''))
            if is_forward:
                f = f'{pkt[IP].src}-{pkt[IP].dst}-{pkt[IP].sport}-{pkt[IP].dport}-{6 if pkt.haslayer(TCP) else 17}'
            else:
                f = f'{pkt[IP].dst}-{pkt[IP].src}-{pkt[IP].dport}-{pkt[IP].sport}-{6 if pkt.haslayer(TCP) else 17}'
            conn = connections.get(f)
            if conn:
                if pkt.time - conn.start_time > 120:
                    conn.close()
                    with open('flows.csv', 'a') as file:
                        file.write(conn.get_row() + '\n')
                    connections.pop(f)
                    conn = Connection(pkt)
                    connections[f] = conn
                else:
                    conn.add_packet(pkt)
                    if pkt.haslayer(TCP) and ('F' in pkt[TCP].flags and conn.get_total_packets() > 1):
                        conn.close()
                        with open('flows.csv', 'a') as file:
                            file.write(conn.get_row() + '\n')
                        connections.pop(f)
            else:
                conn = Connection(pkt)
                connections[f] = conn
    sniffer = sniff(prn=packet_process)

sniff_flows()
