from scapy.all import RawPcapReader, Ether, IP, TCP, rdpcap, sniff
from datetime import datetime, timezone
from time import sleep

# check direction (?)

# Flow ID - V
# Source IP - V
# Source Port - V
# Destination IP - V
# Destination Port - V
# Protocol - V
# Timestamp - V
# Flow Duration - V
# Total Fwd Packets - V
# Total Backward Packets - V
# Total Length of Fwd Packets
# Total Length of Bwd Packets
# Fwd Packet Length Max
# Fwd Packet Length Min
# Fwd Packet Length Mean
# Fwd Packet Length Std
# Bwd Packet Length Max
# Bwd Packet Length Min
# Bwd Packet Length Mean
# Bwd Packet Length Std
# Flow Bytes/s
# Flow Packets/s
# Flow IAT Mean
# Flow IAT Std
# Flow IAT Max
# Flow IAT Min
# Fwd IAT Total
# Fwd IAT Mean
# Fwd IAT Std
# Fwd IAT Max
# Fwd IAT Min
# Bwd IAT Total
# Bwd IAT Mean
# Bwd IAT Std
# Bwd IAT Max
# Bwd IAT Min
# Fwd PSH Flags
# Bwd PSH Flags
# Fwd URG Flags
# Bwd URG Flags
# Fwd Header Length
# Bwd Header Length
# Fwd Packets/s
# Bwd Packets/s
# Min Packet Length
# Max Packet Length
# Packet Length Mean
# Packet Length Std
# Packet Length Variance
# FIN Flag Count
# SYN Flag Count
# RST Flag Count
# PSH Flag Count
# ACK Flag Count
# URG Flag Count
# CWE Flag Count
# ECE Flag Count
# Down/Up Ratio
# Average Packet Size
# Avg Fwd Segment Size
# Avg Bwd Segment Size
# Fwd Header Length
# Fwd Avg Bytes/Bulk
# Fwd Avg Packets/Bulk
# Fwd Avg Bulk Rate
# Bwd Avg Bytes/Bulk
# Bwd Avg Packets/Bulk
# Bwd Avg Bulk Rate
# Subflow Fwd Packets
# Subflow Fwd Bytes
# Subflow Bwd Packets
# Subflow Bwd Bytes
# Init_Win_bytes_forward
# Init_Win_bytes_backward
# act_data_pkt_fwd
# min_seg_size_forward
# Active Mean
# Active Std
# Active Max
# Active Min
# Idle Mean
# Idle Std
# Idle Max
# Idle Min
# Label

class Connection():
    def __init__(self, packet):
        if int(packet[IP].src.replace('.', '')) < int(packet[IP].dst.replace('.', '')):
            self.src = packet[IP].src
            self.dst = packet[IP].dst
            self.sport = packet[IP].sport
            self.dport = packet[IP].dport
        else:
            self.src = packet[IP].dst
            self.dst = packet[IP].src
            self.sport = packet[IP].dport
            self.dport = packet[IP].sport
        self.start_time = float(packet.time)
        self.active = True
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.total_len_fwd_packets = 0
        self.total_len_bwd_packets = 0
        self.fit_packet(packet)
    
    def get_flow_id(self):
        return f'{self.src}-{self.dst}-{self.sport}-{self.dport}'

    def fit_packet(self, packet):
        if (packet[IP].src == self.src and packet[IP].dst == self.dst):
            self.total_fwd_packets += 1
            self.total_len_fwd_packets += packet.len
        if (packet[IP].src == self.dst and packet[IP].dst == self.src):
            self.total_bwd_packets += 1
            self.total_len_bwd_packets += packet.len
        self.last_packet_time = packet.time
        
    def get_total_packets(self):
        return self.total_fwd_packets + self.total_bwd_packets

    def this_conn(self, packet):
        return self.active and \
               ((packet[IP].src == self.src and packet[IP].dst == self.dst and \
                 packet[IP].sport == self.sport and packet[IP].dport == self.dport) or \
                (packet[IP].src == self.dst and packet[IP].dst == self.src and \
                 packet[IP].sport == self.dport and packet[IP].dport == self.sport))

    def is_active(self):
        return self.active
    
    
    def close(self):
        self.active = False
    
    def __str__(self):
        return f'{self.get_flow_id()},{self.total_fwd_packets},{self.total_bwd_packets},{self.total_len_fwd_packets},{self.total_len_bwd_packets}'
        # return f'<{self.get_flow_id()},{self.total_fwd_packets},{self.total_bwd_packets},{datetime.fromtimestamp(self.start_time, tz=timezone.utc)},{round((self.last_packet_time - self.start_time)*1000000)}>'


connections = []
closed_connections = []


#pcap = rdpcap('test123.pcap')
def pkt_callback(pkt):
    # for i in connections:
    #     print(i)
    # print('-------')
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        conn = None
        for c in connections:
            if c.this_conn(pkt):
                conn = c
                break
        if conn:
            if pkt.time - conn.start_time > 120:
                conn.close()
                closed_connections.append(conn)
                print(conn)
                connections.remove(conn)
                conn = Connection(pkt)
                connections.append(conn)
            else:
                conn.fit_packet(pkt)
                if ('F' in pkt[TCP].flags and conn.get_total_packets() > 1):
                    conn.close()
                    closed_connections.append(conn)
                    print(conn)
                    connections.remove(conn)
        else:
            conn = Connection(pkt)
            connections.append(conn)


pcap = sniff(prn=pkt_callback)
