from flask import Flask, render_template, request, abort
from celery import Celery
from redis import Redis

app = Flask(__name__)
celery_client = Celery('main', broker='redis://redis:6379', backend='redis://redis:6379')
task = None
redis = Redis(host='redis', port=6379)

@app.route('/start')
def start():
    redis.set('started', 'true')
    task = celery_client.send_task('main.sniff_flows')
    task = celery_client.send_task('main.train')
    return str(task.status)

@app.route('/stop')
def stop():
    #i = celery_client.control.inspect()
    #for j in i.active().keys():
    #    for k in i.active()[j]:
    #        celery_client.control.revoke(k['id'], terminate=True, signal='SIGKILL')
    #return str(i.active())
    redis.set('started', 'false')

@app.route('/status')
def status():
    i = celery_client.control.inspect()
    return str(i.active())

if __name__ == '__main__':
    app.run('0.0.0.0')
