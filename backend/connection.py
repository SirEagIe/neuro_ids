from scapy.all import RawPcapReader, Ether, IP, TCP, UDP, rdpcap
from datetime import datetime, timezone
from time import sleep
from statistics import mean, stdev, variance


SESSION_TIMEOUT = 120 # seconds


class Connection():
    def __init__(self, packet):
        self.src = packet[IP].src                        # Source IP
        self.sport = packet[IP].sport                    # Source Port
        self.dst = packet[IP].dst                        # Destination IP
        self.dport = packet[IP].dport                    # Destination Port
        self.protocol = 6 if packet.haslayer(TCP) \
            else (17 if packet.haslayer(UDP) else 0)     # Protocol
        self.start_time = float(packet.time)             # Timestamp (seconds)
        self.duration = 0                                # Flow Duration (microseconds)
        self.total_fwd_packets = 0                       # Total Fwd Packets
        self.total_bwd_packets = 0                       # Total Backward Packets
        self.len_fwd_packets_total = 0                   # Total Length of Fwd Packets
        self.len_bwd_packets_total = 0                   # Total Length of Bwd Packets
        self.len_fwd_packets_max = 0                     # Fwd Packet Length Max
        self.len_fwd_packets_min = 0                     # Fwd Packet Length Min
        self.len_fwd_packets_mean = 0                    # Fwd Packet Length Mean
        self.len_fwd_packets_std = 0                     # Fwd Packet Length Std
        self.len_bwd_packets_max = 0                     # Bwd Packet Length Max
        self.len_bwd_packets_min = 0                     # Bwd Packet Length Min
        self.len_bwd_packets_mean = 0                    # Bwd Packet Length Mean
        self.len_bwd_packets_std = 0                     # Bwd Packet Length Std
        self.flow_bytes_per_second = 0                   # Flow Bytes/s
        self.flow_packets_per_second = 0                 # Flow Packets/s
        self.flow_iat_mean = 0                           # Flow IAT Mean
        self.flow_iat_std = 0                            # Flow IAT Std
        self.flow_iat_max = 0                            # Flow IAT Max
        self.flow_iat_min = 0                            # Flow IAT Min
        self.fwd_iat_total = 0                           # Fwd IAT Total
        self.fwd_iat_mean = 0                            # Fwd IAT Mean
        self.fwd_iat_std = 0                             # Fwd IAT Std
        self.fwd_iat_max = 0                             # Fwd IAT Max
        self.fwd_iat_min = 0                             # Fwd IAT Min
        self.bwd_iat_total = 0                           # Bwd IAT Total
        self.bwd_iat_mean = 0                            # Bwd IAT Mean
        self.bwd_iat_std = 0                             # Bwd IAT Std
        self.bwd_iat_max = 0                             # Bwd IAT Max
        self.bwd_iat_min = 0                             # Bwd IAT Min
        self.flag_count = {
            'F': 0,                                      # FIN Flag Count
            'S': 0,                                      # SYN Flag Count
            'R': 0,                                      # RST Flag Count
            'P': 0,                                      # PSH Flag Count
            'A': 0,                                      # ACK Flag Count
            'U': 0,                                      # URG Flag Count
            'C': 0,                                      # CWE Flag Count
            'E': 0,                                      # ECE Flag Count
            
        }
        self.fwd_header_len = 0                          # Fwd Header Length
        self.bwd_header_len = 0                          # Bwd Header Length
        self.fwd_packets_per_second = 0                  # Fwd Packets/s
        self.bwd_packets_per_second = 0                  # Bwd Packets/s
        self.len_packet_min = 0                          # Min Packet Length
        self.len_packet_max = 0                          # Max Packet Length
        self.len_packet_mean = 0                         # Packet Length Mean
        self.len_packet_std = 0                          # Packet Length Std
        self.len_packet_var = 0                          # Packet Length Variance
        self.down_up_ratio = 0                           # Down/Up Ratio
        self.fwd_init_win_bytes = 0                      # Init_Win_bytes_forward
        self.bwd_init_win_bytes = 0                      # Init_Win_bytes_backward
        self.act_data_pkt_fwd = 0                        # act_data_pkt_fwd
        self.active_mean = 0                             # Active Mean
        self.active_std = 0                              # Active Std
        self.active_max = 0                              # Active Max
        self.active_min = 0                              # Active Min
        self.idle_mean = 0                               # Idle Mean
        self.idle_std = 0                                # Idle Std
        self.idle_max = 0                                # Idle Max
        self.idle_min = 0                                # Idle Min
        self.label = 1 if self.src == '172.16.0.1' and self.dport == 80 else 0
        self.fwd_packets_sizes = []
        self.bwd_packets_sizes = []
        self.fwd_packets_timestamps = []
        self.bwd_packets_timestamps = []
        self.last_packet_time = float(packet.time)
        self.start_active = float(packet.time)
        self.active = []
        self.idle = []
        self.is_forward = int(self.src.replace('.', '')) < int(self.dst.replace('.', ''))
        self.add_packet(packet)

    
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

    def add_packet(self, packet):
        packet_l4 = packet[TCP] if packet.haslayer(TCP) else (packet[UDP] if packet.haslayer(UDP) else None)
        if (packet[IP].src == self.src and packet[IP].dst == self.dst):
            self.total_fwd_packets += 1
            self.fwd_packets_sizes.append(len(packet_l4.payload))
            self.fwd_packets_timestamps.append(int(packet.time * 10 ** 6))
            self.fwd_header_len += len(packet_l4) - len(packet_l4.payload)
            if self.fwd_init_win_bytes == 0 and packet.haslayer(TCP):
                self.fwd_init_win_bytes = packet_l4.window
            if len(packet_l4.payload) > 0:
                self.act_data_pkt_fwd += 1
        if (packet[IP].src == self.dst and packet[IP].dst == self.src):
            self.total_bwd_packets += 1
            self.bwd_packets_sizes.append(len(packet_l4.payload))
            self.bwd_packets_timestamps.append(int(packet.time * 10 ** 6))
            self.bwd_header_len += len(packet_l4) - len(packet_l4.payload)
            if packet.haslayer(TCP):
                self.bwd_init_win_bytes = packet_l4.window
        if packet.haslayer(TCP):
            for flag in packet_l4.flags:
                self.flag_count[flag] += 1
        if packet.time - self.last_packet_time > 0.005:
            self.idle.append((packet.time - self.last_packet_time) * 10 ** 6)
            if self.last_packet_time - self.start_active > 0:
                self.active.append((self.last_packet_time - self.start_active) * 10 ** 6)
            self.start_active = packet.time
        self.last_packet_time = packet.time


    def recalculation_statistics(self):
        self.duration = self.last_packet_time - self.start_time
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
        self.flow_bytes_per_second = (sum(self.fwd_packets_sizes) + sum(self.bwd_packets_sizes)) / self.duration if self.duration != 0 else 0
        self.flow_packets_per_second = (self.total_fwd_packets + self.total_bwd_packets) / self.duration if self.duration != 0 else 0
        # IAT
        packets_timestamps = sorted(self.fwd_packets_timestamps + self.bwd_packets_timestamps)
        iat_packets = [packets_timestamps[i + 1] - packets_timestamps[i] for i in range(len(packets_timestamps) - 1)]
        self.flow_iat_mean = mean(iat_packets) if iat_packets else 0
        self.flow_iat_std = stdev(iat_packets) if len(iat_packets) > 1 else 0
        self.flow_iat_max = max(iat_packets) if iat_packets else 0
        self.flow_iat_min = min(iat_packets) if iat_packets else 0
        fwd_iat_packets = [self.fwd_packets_timestamps[i + 1] - self.fwd_packets_timestamps[i] for i in range(len(self.fwd_packets_timestamps) - 1)]
        self.fwd_iat_total = sum(fwd_iat_packets)
        self.fwd_iat_mean = mean(fwd_iat_packets) if fwd_iat_packets else 0
        self.fwd_iat_std = stdev(fwd_iat_packets) if len(fwd_iat_packets) > 1 else 0
        self.fwd_iat_max = max(fwd_iat_packets) if fwd_iat_packets else 0
        self.fwd_iat_min = min(fwd_iat_packets) if fwd_iat_packets else 0
        bwd_iat_packets = [self.bwd_packets_timestamps[i + 1] - self.bwd_packets_timestamps[i] for i in range(len(self.bwd_packets_timestamps) - 1)]
        self.bwd_iat_total = sum(bwd_iat_packets)
        self.bwd_iat_mean = mean(bwd_iat_packets) if bwd_iat_packets else 0
        self.bwd_iat_std = stdev(bwd_iat_packets) if len(bwd_iat_packets) > 1 else 0
        self.bwd_iat_max = max(bwd_iat_packets) if bwd_iat_packets else 0
        self.bwd_iat_min = min(bwd_iat_packets) if bwd_iat_packets else 0
        self.fwd_packets_per_second = self.total_fwd_packets / self.duration if self.duration != 0 else 0
        self.bwd_packets_per_second = self.total_bwd_packets / self.duration if self.duration != 0 else 0
        packets_sizes = self.fwd_packets_sizes + self.fwd_packets_sizes
        self.len_packet_min = min(packets_sizes) if packets_sizes else 0
        self.len_packet_max = max(packets_sizes) if packets_sizes else 0
        self.len_packet_mean = mean(packets_sizes) if packets_sizes else 0
        self.len_packet_std = stdev(packets_sizes) if len(packets_sizes) > 1 else 0
        self.len_packet_var = variance(packets_sizes) if packets_sizes else 0
        self.down_up_ratio = self.len_bwd_packets_total / self.len_fwd_packets_total if self.len_fwd_packets_total > 0 else 0
        self.active_mean = mean(self.active) if self.active else 0
        self.active_std = stdev(self.active) if len(self.active) > 1 else 0
        self.active_max = max(self.active) if self.active else 0
        self.active_min = min(self.active) if self.active else 0
        self.idle_mean = mean(self.idle) if self.idle else 0
        self.idle_std = stdev(self.idle) if len(self.idle) > 1 else 0
        self.idle_max = max(self.idle) if self.idle else 0
        self.idle_min = min(self.idle) if self.idle else 0
    
    def get_total_packets(self):
        return self.total_fwd_packets + self.total_bwd_packets

    def this_conn(self, packet):
        return ((packet[IP].src == self.src and packet[IP].dst == self.dst and \
                 packet[IP].sport == self.sport and packet[IP].dport == self.dport) or \
                (packet[IP].src == self.dst and packet[IP].dst == self.src and \
                 packet[IP].sport == self.dport and packet[IP].dport == self.sport))
    
    def close(self):
        self.recalculation_statistics()


    def get_row(self):
        return self.__str__()
    
    
    def __str__(self):
        # return f'{self.get_flow_id()},{self.src},{self.sport},{self.dst},{self.dport},{self.protocol},{datetime.fromtimestamp(self.start_time)},{round(self.duration * 10 ** 6)},\
# {self.total_fwd_packets},{self.total_bwd_packets},{self.len_fwd_packets_total},{self.len_bwd_packets_total},{self.len_fwd_packets_max},\
# {self.len_fwd_packets_min},{round(self.len_fwd_packets_mean, 2)},{round(self.len_fwd_packets_std, 2)},{self.len_bwd_packets_max},{self.len_bwd_packets_min},\
# {round(self.len_bwd_packets_mean, 2)},{round(self.len_bwd_packets_std, 2)},{round(self.flow_bytes_per_second, 2)},{round(self.flow_packets_per_second, 2)},\
# {round(self.flow_iat_mean, 2)},{round(self.flow_iat_std, 2)},{self.flow_iat_max},{self.flow_iat_min},\
# {self.fwd_iat_total},{round(self.fwd_iat_mean, 2)},{round(self.fwd_iat_std, 2)},{self.fwd_iat_max},{self.fwd_iat_min},\
# {self.bwd_iat_total},{round(self.bwd_iat_mean, 2)},{round(self.bwd_iat_std, 2)},{self.bwd_iat_max},{self.bwd_iat_min},\
# {self.fwd_header_len},{self.bwd_header_len},{round(self.fwd_packets_per_second, 2)},{round(self.bwd_packets_per_second, 2)},\
# {self.len_packet_min},{self.len_packet_max},{self.len_packet_mean},{round(self.len_packet_std, 2)},{round(self.len_packet_var, 2)},\
# {int(self.down_up_ratio)},{self.fwd_init_win_bytes},{self.bwd_init_win_bytes},{self.act_data_pkt_fwd},\
# {round(self.active_mean, 2)},{round(self.active_std, 2)},{round(self.active_max, 2)},{round(self.active_min, 2)},\
# {round(self.idle_mean, 2)},{round(self.idle_std, 2)},{round(self.idle_max, 2)},{round(self.idle_min, 2)}'
# {",".join(map(lambda f: str(f), self.flag_count.values()))}'
        return f'{self.get_flow_id()},\
{self.src},\
{self.sport},\
{self.dst},\
{self.dport},\
{self.protocol},\
{self.start_time},\
{self.duration * 10 ** 6},\
{self.total_fwd_packets},\
{self.total_bwd_packets},\
{self.len_fwd_packets_total},\
{self.len_bwd_packets_total},\
{self.len_fwd_packets_max},\
{self.len_fwd_packets_min},\
{self.len_fwd_packets_mean},\
{self.len_fwd_packets_std},\
{self.len_bwd_packets_max},\
{self.len_bwd_packets_min},\
{self.len_bwd_packets_mean},\
{self.len_bwd_packets_std},\
{self.flow_bytes_per_second},\
{self.flow_packets_per_second},\
{self.flow_iat_mean},\
{self.flow_iat_std},\
{self.flow_iat_max},\
{self.flow_iat_min},\
{self.fwd_iat_total},\
{self.fwd_iat_mean},\
{self.fwd_iat_std},\
{self.fwd_iat_max},\
{self.fwd_iat_min},\
{self.bwd_iat_total},\
{self.bwd_iat_mean},\
{self.bwd_iat_std},\
{self.bwd_iat_max},\
{self.bwd_iat_min},\
{",".join(map(lambda f: str(f), self.flag_count.values()))},\
{self.fwd_header_len},\
{self.bwd_header_len},\
{self.fwd_packets_per_second},\
{self.bwd_packets_per_second},\
{self.len_packet_min},\
{self.len_packet_max},\
{self.len_packet_mean},\
{self.len_packet_std},\
{self.len_packet_var},\
{self.down_up_ratio},\
{self.fwd_init_win_bytes},\
{self.bwd_init_win_bytes},\
{self.act_data_pkt_fwd},\
{self.active_mean},\
{self.active_std},\
{self.active_max},\
{self.active_min},\
{self.idle_mean},\
{self.idle_std},\
{self.idle_max},\
{self.idle_min}'


