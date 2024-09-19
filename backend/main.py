import os
import pickle
from celery import Celery
from scapy.all import sniff, Ether, IP, TCP, UDP
from connection import Connection
from redis import Redis


from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier


celery_client = Celery('main', broker='redis://redis:6379', backend='redis://redis:6379')
redis = Redis(host='redis', port=6379)


@celery_client.task
def sniff_flows_train():
    os.remove('flows.csv')
    connections = {}
    def packet_process(pkt):
        if redis.get('started') == b'false':
            with open('flows.csv', 'a') as file:
                for conn in connections.values():
                    file.write(conn.get_row() + '\n')
            train()
            exit(0)
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

import random

@celery_client.task
def sniff_flows_detect():
    os.remove('flows.csv')
    connections = {}
    def packet_process(pkt):
        if redis.get('started') == b'false':
            with open('flows.csv', 'a') as file:
                for conn in connections.values():
                    file.write(conn.get_row() + '\n')
            train()
            exit(0)
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
                        detect(conn.get_row())
                    connections.pop(f)
                    conn = Connection(pkt)
                    connections[f] = conn
                else:
                    conn.add_packet(pkt)
                    if pkt.haslayer(TCP) and ('F' in pkt[TCP].flags and conn.get_total_packets() > 1):
                        conn.close()
                        with open('flows.csv', 'a') as file:
                            file.write(conn.get_row() + '\n')
                            detect(conn.get_row())
                        connections.pop(f)
            else:
                conn = Connection(pkt)
                connections[f] = conn
    sniffer = sniff(prn=packet_process)


def train():
    clf = None
    if os.path.isfile('model.pkl'):
        with open('model.pkl', 'rb') as f:
            clf = pickle.load(f)
    else:
        clf = RandomForestClassifier(n_estimators=50)

    flows = []
    labels = []
    with open('flows.csv', 'r') as file:
        for line in file.readlines():
            flows.append(line.split(',')[7:-1])
            labels.append(random.randint(0, 1))   

    clf.fit(flows, labels)
    with open('model.pkl', 'wb') as f:
        pickle.dump(clf, f)


def detect(flow):
    clf = None
    if os.path.isfile('model.pkl'):
        with open('model.pkl', 'rb') as f:
            clf = pickle.load(f)
        flow = flow.split(',')
        predict = clf.predict([flow[7:-1]])
        with open('alarm', 'a+') as file:
            file.write(str(flow[0]) + ' ' + str(predict) + '\n')

