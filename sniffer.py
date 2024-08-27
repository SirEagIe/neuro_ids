from scapy.all import RawPcapReader, Ether, IP, TCP, rdpcap
from datetime import datetime, timezone
from time import sleep
from statistics import mean, stdev

SESSION_TIMEOUT = 120 # seconds


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
# Total Length of Fwd Packets - V
# Total Length of Bwd Packets - V
# Fwd Packet Length Max - V
# Fwd Packet Length Min - V
# Fwd Packet Length Mean - V
# Fwd Packet Length Std - V
# Bwd Packet Length Max - V
# Bwd Packet Length Min - V
# Bwd Packet Length Mean - V
# Bwd Packet Length Std - V
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
        self.src = packet[IP].src                      # Source IP
        self.sport = packet[IP].sport                  # Source Port
        self.dst = packet[IP].dst                      # Destination IP
        self.dport = packet[IP].dport                  # Destination Port
        self.protocol = 6 if packet.haslayer(TCP) \
            else (17 if packet.haslayer(UDP) else 0)   # Protocol
        self.start_time = float(packet.time)           # Timestamp (seconds)
        self.duration = 0                              # Flow Duration (microseconds)
        self.total_fwd_packets = 0                     # Total Fwd Packets
        self.total_bwd_packets = 0                     # Total Backward Packets
        self.len_fwd_packets_total = 0                 # Total Length of Fwd Packets
        self.len_bwd_packets_total = 0                 # Total Length of Bwd Packets
        self.len_fwd_packets_max = 0                   # Fwd Packet Length Max
        self.len_fwd_packets_min = 0                   # Fwd Packet Length Min
        self.len_fwd_packets_mean = 0                  # Fwd Packet Length Mean
        self.len_fwd_packets_std = 0                   # Fwd Packet Length Std
        self.len_bwd_packets_max = 0                   # Bwd Packet Length Max
        self.len_bwd_packets_min = 0                   # Bwd Packet Length Min
        self.len_bwd_packets_mean = 0                  # Bwd Packet Length Mean
        self.len_bwd_packets_std = 0                   # Bwd Packet Length Std
        
        self.fwd_packets_sizes = []
        self.bwd_packets_sizes = []
        self.last_packet_time = float(packet.time)
        self.active = True
        self.is_forward = int(self.src.replace('.', '')) < int(self.dst.replace('.', ''))
        self.fit_packet(packet)

    
    def get_flow_id(self):
        if self.is_forward:
            src = self.src
            dst = self.dst
            sport = self.sport
            dport = self.dport
        else:
            src = self.dst
            dst = self.src
            sport = self.dport
            dport = self.sport
        return f'{src}-{dst}-{sport}-{dport}-{self.protocol}'

    def fit_packet(self, packet):
        if (packet[IP].src == self.src and packet[IP].dst == self.dst):
            self.total_fwd_packets += 1
            self.fwd_packets_sizes.append(len(packet[TCP].payload))
        if (packet[IP].src == self.dst and packet[IP].dst == self.src):
            self.total_bwd_packets += 1
            self.bwd_packets_sizes.append(len(packet[TCP].payload))
        self.last_packet_time = packet.time

    def recalculation_statistics(self):
        self.duration = round((self.last_packet_time - self.start_time) * 10 ** 6)
        self.len_fwd_packets_total = sum(self.fwd_packets_sizes)
        self.len_bwd_packets_total = sum(self.bwd_packets_sizes)
        self.len_fwd_packets_max = max(self.fwd_packets_sizes) if self.fwd_packets_sizes else 0
        self.len_fwd_packets_min = min(self.fwd_packets_sizes) if self.fwd_packets_sizes else 0
        self.len_fwd_packets_mean = mean(self.fwd_packets_sizes) if self.fwd_packets_sizes else 0
        self.len_fwd_packets_std = stdev(self.fwd_packets_sizes) if len(self.fwd_packets_sizes) > 1 else 0
        self.len_bwd_packets_max = max(self.bwd_packets_sizes) if self.bwd_packets_sizes else 0
        self.len_bwd_packets_min = min(self.bwd_packets_sizes) if self.bwd_packets_sizes else 0
        self.len_bwd_packets_mean = mean(self.bwd_packets_sizes) if self.bwd_packets_sizes else 0
        self.len_bwd_packets_std = stdev(self.bwd_packets_sizes) if len(self.bwd_packets_sizes) > 1 else 0
        
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
        self.recalculation_statistics()
        self.active = False
    
    def __str__(self):
        # return f'{self.get_flow_id()},{self.total_fwd_packets},{self.total_bwd_packets},{sum(self.fwd_packets_sizes)},{sum(self.bwd_packets_sizes)},{max(self.fwd_packets_sizes)},{min(self.fwd_packets_sizes)},{mean(self.fwd_packets_sizes)},{stdev(self.fwd_packets_sizes)},{max(self.bwd_packets_sizes)},{min(self.bwd_packets_sizes)},{mean(self.bwd_packets_sizes)},{stdev(self.bwd_packets_sizes)}'
        # return f'<{self.get_flow_id()},{self.total_fwd_packets},{self.total_bwd_packets},{datetime.fromtimestamp(self.start_time, tz=timezone.utc)},{round((self.last_packet_time - self.start_time)*1000000)}>'
        return f'{self.get_flow_id()},{self.src},{self.sport},{self.dst},{self.dport},{self.protocol},{datetime.fromtimestamp(self.start_time)},{self.duration},{self.total_fwd_packets},{self.total_bwd_packets},\
{self.len_fwd_packets_total},{self.len_fwd_packets_total},{self.len_fwd_packets_total},{self.len_fwd_packets_max},{self.len_fwd_packets_min},{self.len_fwd_packets_mean},{self.len_fwd_packets_std},\
{self.len_bwd_packets_max},{self.len_bwd_packets_min},{self.len_bwd_packets_mean},{self.len_bwd_packets_std}'


connections = []
closed_connections = []


pcap = rdpcap('test123.pcap')
for pkt in pcap:
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
            if pkt.time - conn.start_time > SESSION_TIMEOUT:
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



print('--------')
for i in connections:
    i.close()
    print(i)



