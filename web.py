from flask import Flask, render_template
from sklearn.neural_network import MLPClassifier
import sqlite3
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def foo():
    db = sqlite3.connect('ids.db')
    cursor = db.cursor()
    cursor.execute("""SELECT * FROM sessions WHERE label LIKE 'BENIGN'""")
    l = cursor.fetchall()
    cursor.execute("""SELECT * FROM sessions WHERE label NOT LIKE 'BENIGN'""")
    nl = cursor.fetchall()
    db.close()
    return render_template('index.html', l=l, nl=nl, to_datetime=datetime.fromtimestamp)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port='8888')
