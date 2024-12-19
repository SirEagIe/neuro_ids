from flask import Flask, render_template, redirect
from sklearn.neural_network import MLPClassifier
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
db = sqlite3.connect('ids.db')
cursor = db.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    src TEXT,
    dst TEXT,
    start_time INTEGER,
    label TEXT
)''')
db.commit()
db.close()

@app.route('/')
def index():
    return redirect('/dashboard', code=302)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/incidents')
def incidents():
    return render_template('incidents.html')

@app.route('/incidents-data')
def incidents_data():
    db = sqlite3.connect('ids.db')
    cursor = db.cursor()
    cursor.execute("""SELECT src, dst, min(start_time), label as start_time FROM sessions GROUP BY src, dst, label HAVING count(*) > 10 AND label NOT LIKE 'BENIGN'""")
    data = cursor.fetchall()
    for d in data:
        cursor.execute(f"""SELECT * FROM incidents WHERE src='{d[0]}' AND dst='{d[1]}' AND start_time={d[2]} AND label='{d[3]}'""")
        if not cursor.fetchall():
            cursor.execute(f"""INSERT INTO incidents (src, dst, start_time, label) VALUES ('{d[0]}', '{d[1]}', {d[2]}, '{d[3]}');""")
        db.commit()
    cursor.execute("""SELECT id, src, dst, datetime(start_time, 'unixepoch') as start_time, label FROM incidents ORDER BY id DESC""")
    data = cursor.fetchall()
    db.close()
    return {'data': data}
    

@app.route('/data-benign')
def data_benign():
    db = sqlite3.connect('ids.db')
    cursor = db.cursor()
    cursor.execute("""SELECT flow, src, sport, dst, dport, protocol, datetime(start_time, 'unixepoch') as start_time, duration, total_fwd_packets, len_fwd_packets_total, len_fwd_packets_max, len_fwd_packets_mean, flow_iat_min, fwd_iat_std, fwd_iat_max, fwd_iat_min, fwd_header_len, len_packet_max, len_packet_mean, label FROM sessions WHERE label LIKE 'BENIGN'""")
    data = cursor.fetchall()
    db.close()
    header = ['flow', 'src', 'sport', 'dst', 'dport', 'protocol', 'start_time', 'duration', 'total_fwd_packets', 'len_fwd_packets_total', 'len_fwd_packets_max', 'len_fwd_packets_mean', 'flow_iat_min', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'fwd_header_len', 'len_packet_max', 'len_packet_mean', 'label']
    return {
        'data': [dict(zip(header, d)) for d in data]
    }

@app.route('/data-malicious')
def data_malicious():
    db = sqlite3.connect('ids.db')
    cursor = db.cursor()
    cursor.execute("""SELECT flow, src, sport, dst, dport, protocol, datetime(start_time, 'unixepoch') as start_time, duration, total_fwd_packets, len_fwd_packets_total, len_fwd_packets_max, len_fwd_packets_mean, flow_iat_min, fwd_iat_std, fwd_iat_max, fwd_iat_min, fwd_header_len, len_packet_max, len_packet_mean, label FROM sessions WHERE label NOT LIKE 'BENIGN'""")
    data = cursor.fetchall()
    db.close()
    header = ['flow', 'src', 'sport', 'dst', 'dport', 'protocol', 'start_time', 'duration', 'total_fwd_packets', 'len_fwd_packets_total', 'len_fwd_packets_max', 'len_fwd_packets_mean', 'flow_iat_min', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'fwd_header_len', 'len_packet_max', 'len_packet_mean', 'label']
    return {
        'data': [dict(zip(header, d)) for d in data]
    }

def rotate_db():
    incidents_data()
    db = sqlite3.connect('ids.db')
    cursor = db.cursor()
    cursor.execute("""DELETE FROM sessions WHERE start_time < (julianday('now') - 2440587.5) * 86400.0 - 3600""")
    db.commit()
    cursor.execute("""SELECT start_time,(julianday('now') - 2440587.5) * 86400.0 FROM sessions""")
    db.close()

if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    scheduler.add_job(rotate_db, trigger='interval', id='rotate_db', seconds=3600)
    scheduler.start()
    app.run(debug=True, host='0.0.0.0', port='8888')
