from flask import Flask, render_template, request, abort
from celery import Celery
from redis import Redis

app = Flask(__name__)
celery_client = Celery('main', broker='redis://redis:6379', backend='redis://redis:6379')
task = None
redis = Redis(host='redis', port=6379)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_train')
def start_train():
    if redis.get('started') == b'true':
        return {'code': '403'}
    redis.set('started', 'true')
    task = celery_client.send_task('main.sniff_flows_train')
    return {'code': '200'}

@app.route('/start_detect')
def start_detect():
    if redis.get('started') == b'true':
        return {'code': '403'}
    redis.set('started', 'true')
    task = celery_client.send_task('main.sniff_flows_detect')
    return {'code': '200'}

@app.route('/stop')
def stop():
    redis.set('started', 'false')
    return {'code': '200'}

@app.route('/status')
def status():
    i = celery_client.control.inspect().active()
    r = redis.get('started')
    if list(i.values()) == [[]] and (r == b'false' or not r):
        return {'status': 'stopped'}
    elif list(i.values()) == [[]] and r == b'true':
        return {'status': 'starting...'}
    elif list(i.values())[0][0].get('name') == 'main.sniff_flows_train' and r == b'true':
        return {'status': 'sniff for tarin'}
    elif list(i.values())[0][0].get('name') == 'main.sniff_flows_train' and r == b'false':
        return {'status': 'model tarin'}
    elif list(i.values())[0][0].get('name') == 'main.sniff_flows_detect' and r == b'true':
        return {'status': 'detect'}
    elif list(i.values())[0][0].get('name') == 'main.sniff_flows_detect' and r == b'false':
        return {'status': 'stoping...'}
    return {'status': '...'}

if __name__ == '__main__':
    app.run('0.0.0.0')
