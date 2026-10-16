"""Run the nine API groups as local HTTP services behind one Postman URL."""
import multiprocessing
import os
import secrets
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from flask import Flask, Response, request, jsonify
from app import create_app
from common import OWNERS

GROUPS = ('users', 'assets', 'incidents', 'threats', 'logs', 'reports',
          'vulnerabilities', 'notifications', 'playbooks')
URLS = {name: f'http://127.0.0.1:{5101 + i}' for i, name in enumerate(GROUPS)}


def run_service(name):
    app = create_app({'SERVICE_URLS': URLS}, service=name)
    app.run(host='127.0.0.1', port=int(URLS[name].rsplit(':', 1)[1]), use_reloader=False)


def gateway():
    app = Flask('gateway')

    @app.get('/health')
    def health():
        return {'status': 'ok', 'services': list(GROUPS)}

    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
    def forward(path):
        parts = path.split('/')
        group = parts[1] if len(parts) > 1 else ''
        if group == 'actions':
            group = 'playbooks'
        if group not in URLS or parts[0] != OWNERS.get(group):
            return jsonify(status='error', message='Service not found'), 404
        url = URLS[group] + '/' + path
        if request.query_string:
            url += '?' + request.query_string.decode()
        headers = {key: value for key, value in request.headers.items()
                   if key.lower() in ('authorization', 'content-type')}
        outgoing = Request(url, data=request.get_data() if request.method in ('POST', 'PUT') else None,
                           headers=headers, method=request.method)
        try:
            with urlopen(outgoing, timeout=10) as reply:
                return Response(reply.read(), reply.status, content_type=reply.headers.get('Content-Type', 'application/json'))
        except HTTPError as err:
            return Response(err.read(), err.code, content_type='application/json')
        except URLError:
            return jsonify(status='error', message='Service is unavailable'), 502

    app.run(host='127.0.0.1', port=5000, use_reloader=False)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    os.environ.setdefault('SECRET_KEY', secrets.token_urlsafe(32))
    children = [multiprocessing.Process(target=run_service, args=(name,), name=name) for name in GROUPS]
    for child in children:
        child.start()
    try:
        gateway()
    finally:
        for child in children:
            child.terminate()
        for child in children:
            child.join()
