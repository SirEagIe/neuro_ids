from scapy.all import RawPcapReader, Ether, IP, TCP, UDP, rdpcap, PcapReader, sniff
from datetime import datetime, timezone
from time import sleep, time
from statistics import mean, stdev, variance
from redis import Redis
from apscheduler.schedulers.background import BackgroundScheduler


redis = Redis(host='127.0.0.1', port=6379)

SESSION_TIMEOUT = 10 # seconds


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
        self.len_fwd_packets_total = 0                   # Total Length of Fwd Packets
        self.len_fwd_packets_mean = 0                    # Fwd Packet Length Mean
        self.len_fwd_packets_max = 0                     # Fwd Packet Length Max
        self.flow_iat_min = 0                            # Flow IAT Min
        self.fwd_iat_std = 0                             # Fwd IAT Std
        self.fwd_iat_max = 0                             # Fwd IAT Max
        self.fwd_iat_min = 0                             # Fwd IAT Min
        self.fwd_header_len = 0                          # Fwd Header Length
        self.len_packet_max = 0                          # Max Packet Length
        self.len_packet_mean = 0                         # Packet Length Mean
        self.label = None
        self.total_packets = 0
        self.fwd_packets_sizes = []
        self.fwd_packets_timestamps = []
        self.bwd_packets_timestamps = []
        self.last_packet_time = 0
        self.add_packet(packet)


    def get_flow_id(self):
        return f'{self.src}-{self.dst}-{self.sport}-{self.dport}-{self.protocol}'

    def add_packet(self, packet):
        packet_l4 = packet[TCP] if packet.haslayer(TCP) else (packet[UDP] if packet.haslayer(UDP) else None)
        if (packet[IP].src == self.src and packet[IP].dst == self.dst):
            self.total_fwd_packets += 1
            self.fwd_packets_sizes.append(len(packet_l4.payload))
            self.fwd_packets_timestamps.append(int(float(packet.time) * 10 ** 6))
            self.fwd_header_len += len(packet_l4) - len(packet_l4.payload)
        if (packet[IP].src == self.dst and packet[IP].dst == self.src):
            self.bwd_packets_timestamps.append(int(float(packet.time) * 10 ** 6))
        self.last_packet_time = float(packet.time)
        self.total_packets += 1


    def recalculate_stats(self):
        self.duration = self.last_packet_time - self.start_time
        self.len_fwd_packets_total = sum(self.fwd_packets_sizes)
        self.len_fwd_packets_max = max(self.fwd_packets_sizes) if self.fwd_packets_sizes else 0
        self.len_fwd_packets_mean = mean(self.fwd_packets_sizes) if self.fwd_packets_sizes else 0
        # IAT
        packets_timestamps = sorted(self.fwd_packets_timestamps + self.bwd_packets_timestamps)
        iat_packets = [packets_timestamps[i + 1] - packets_timestamps[i] for i in range(len(packets_timestamps) - 1)]
        self.flow_iat_min = min(iat_packets) if iat_packets else 0
        fwd_iat_packets = [self.fwd_packets_timestamps[i + 1] - self.fwd_packets_timestamps[i] for i in range(len(self.fwd_packets_timestamps) - 1)]
        self.fwd_iat_std = stdev(fwd_iat_packets) if len(fwd_iat_packets) > 1 else 0
        self.fwd_iat_max = max(fwd_iat_packets) if fwd_iat_packets else 0
        self.fwd_iat_min = min(fwd_iat_packets) if fwd_iat_packets else 0
        packets_sizes = self.fwd_packets_sizes + self.fwd_packets_sizes
        self.len_packet_max = max(packets_sizes) if packets_sizes else 0
        self.len_packet_mean = mean(packets_sizes) if packets_sizes else 0
    

    def this_conn(self, packet):
        return ((packet[IP].src == self.src and packet[IP].dst == self.dst and \
                 packet[IP].sport == self.sport and packet[IP].dport == self.dport) or \
                (packet[IP].src == self.dst and packet[IP].dst == self.src and \
                 packet[IP].sport == self.dport and packet[IP].dport == self.sport))
    
    def reset(self, packet):
        self.start_time = float(packet.time)             # Timestamp (seconds)
        self.duration = 0                                # Flow Duration (microseconds)
        self.total_fwd_packets = 0                       # Total Fwd Packets
        self.len_fwd_packets_total = 0                   # Total Length of Fwd Packets
        self.len_fwd_packets_mean = 0                    # Fwd Packet Length Mean
        self.len_fwd_packets_max = 0                     # Fwd Packet Length Max
        self.flow_iat_min = 0                            # Flow IAT Min
        self.fwd_iat_std = 0                             # Fwd IAT Std
        self.fwd_iat_max = 0                             # Fwd IAT Max
        self.fwd_iat_min = 0                             # Fwd IAT Min
        self.fwd_header_len = 0                          # Fwd Header Length
        self.len_packet_max = 0                          # Max Packet Length
        self.len_packet_mean = 0                         # Packet Length Mean
        self.total_packets = 0
        self.fwd_packets_sizes = []
        self.fwd_packets_timestamps = []
        self.bwd_packets_timestamps = []
        self.last_packet_time = float(packet.time)
        self.add_packet(packet)


    def get_row(self):
        return self.__str__()
    
    
    def __str__(self):
        return f'{self.get_flow_id()},\
{self.src},\
{self.sport},\
{self.dst},\
{self.dport},\
{self.protocol},\
{self.start_time},\
{self.duration * 10 ** 6},\
{self.total_fwd_packets},\
{self.len_fwd_packets_total},\
{self.len_fwd_packets_max},\
{self.len_fwd_packets_mean},\
{self.flow_iat_min},\
{self.fwd_iat_std},\
{self.fwd_iat_max},\
{self.fwd_iat_min},\
{self.fwd_header_len},\
{self.len_packet_max},\
{self.len_packet_mean}'

connections = {}

def packet_process(pkt):
    if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        f1 = f'{pkt[IP].src}-{pkt[IP].dst}-{pkt[IP].sport}-{pkt[IP].dport}-{6 if pkt.haslayer(TCP) else 17}'
        f2 = f'{pkt[IP].dst}-{pkt[IP].src}-{pkt[IP].dport}-{pkt[IP].sport}-{6 if pkt.haslayer(TCP) else 17}'
        conn = connections.get(f1, connections.get(f2))
        if conn:
            f = conn.get_flow_id()
            if pkt.time - conn.start_time > SESSION_TIMEOUT:
                conn.recalculate_stats()
                redis.lpush('flows', conn.get_row())
                if f in connections.keys(): connections.pop(f)
            else:
                conn.add_packet(pkt)
                if pkt.haslayer(TCP) and \
                    (('F' in pkt[TCP].flags or 'R' in pkt[TCP].flags) and conn.total_packets > 1):
                    conn.recalculate_stats()
                    redis.lpush('flows', conn.get_row())
                    if f in connections.keys(): connections.pop(f)
        else:
            # print(f'new {pkt[IP].src}-{pkt[IP].dst}-{pkt[IP].sport}-{pkt[IP].dport}')
            conn = Connection(pkt)
            connections[f1] = conn

def check_connections():
    print('test')
    connections_temp = connections.copy()
    for f in connections_temp.keys():
        conn = connections_temp[f]
        print(time(), conn.start_time, time() - conn.start_time, SESSION_TIMEOUT)
        if time() - conn.start_time > SESSION_TIMEOUT:
            conn.recalculate_stats()
            redis.lpush('flows', conn.get_row())
            if f in connections.keys(): connections.pop(f)



scheduler = BackgroundScheduler()
scheduler.add_job(check_connections, trigger='interval', id='check_connections', seconds=5)
scheduler.start()
sniffer = sniff(iface=['ens3'], prn=packet_process)
