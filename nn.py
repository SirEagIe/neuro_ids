from redis import Redis
from sklearn.neural_network import MLPClassifier
import pickle
import sqlite3

db = sqlite3.connect('ids.db')
cursor = db.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
    flow TEXT,
    src TEXT,
    sport INT,
    dst TEXT,
    dport INT,
    protocol INT,
    start_time INT,
    duration INT,
    total_fwd_packets INT,
    len_fwd_packets_total INT,
    len_fwd_packets_max INT,
    len_fwd_packets_mean FLOAT,
    flow_iat_min INT,
    fwd_iat_std FLOAT,
    fwd_iat_max INT,
    fwd_iat_min INT,
    fwd_header_len INT,
    len_packet_max INT,
    len_packet_mean FLOAT,
    label TEXT
)''')
db.commit()

clf = None
with open('model.pkl', 'rb') as f:
    clf = pickle.load(f)

redis = Redis(host='127.0.0.1', port=6379)

while True:
    r = redis.brpop('flows')[1].decode('utf-8')
    print(r.split(',')[8:])
    print(r, pr:=clf.predict([list(map(float, r.split(',')[8:]))]))
    cursor.execute(f"""INSERT INTO sessions VALUES (
        '{r.split(',')[0]}',
        '{r.split(',')[1]}',
        {int(r.split(',')[2])},
        '{r.split(',')[3]}',
        {int(r.split(',')[4])},
        {int(r.split(',')[5])},
        {int(float((r.split(',')[6])))},
        {int(float((r.split(',')[7])))},
        {int(r.split(',')[8])},
        {int(r.split(',')[9])},
        {int(r.split(',')[10])},
        {float(r.split(',')[11])},
        {int(r.split(',')[12])},
        {float(r.split(',')[13])},
        {int(r.split(',')[14])},
        {int(r.split(',')[15])},
        {int(r.split(',')[16])},
        {int(r.split(',')[17])},
        {float(r.split(',')[18])},
        '{pr[0]}'
    )""")
    db.commit()
