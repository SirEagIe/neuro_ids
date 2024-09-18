import os
import pickle
from celery import Celery
from scapy.all import sniff, Ether, IP, TCP, UDP
from connection import Connection
from redis import Redis


from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier


redis = Redis(host='redis', port=6379)


def sniff_flows():
    connections = {}
    def packet_process(pkt):
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
                        redis.rpush('FLOWS', conn.get_row())
                    connections.pop(f)
                    conn = Connection(pkt)
                    connections[f] = conn
                else:
                    conn.add_packet(pkt)
                    if pkt.haslayer(TCP) and ('F' in pkt[TCP].flags and conn.get_total_packets() > 1):
                        conn.close()
                        with open('flows.csv', 'a') as file:
                            file.write(conn.get_row() + '\n')
                            redis.rpush('FLOWS', conn.get_row())
                        connections.pop(f)
            else:
                conn = Connection(pkt)
                connections[f] = conn
    sniffer = sniff(prn=packet_process)

import random
def train():
    clf = None
    if os.path.isfile('model.pkl'):
        with open('model.pkl', 'rb') as f:
            clf = pickle.load(f)
    else:
        clf = RandomForestClassifier(n_estimators=50)
    i=0
    while True:
        flow = redis.rpop('FLOWS')
        flow = flow.decode().split(',')
        clf.fit([flow[7:-1]], [random.randint(0, 1)])
        with open('model.pkl', 'wb') as f:
            pickle.dump(clf, f)
        with open('asd.txt', 'w+') as f:
            d.write(str(i))
            i += 1

sniff_flows()
