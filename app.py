import os
import secrets
import sqlite3
from flask import Flask, jsonify, request, abort
from werkzeug.exceptions import HTTPException
from db import close_db, init_db
from common import OWNERS


def create_app(test_config=None, service=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get('DATABASE', os.path.join(os.path.dirname(__file__), 'data', 'security.db')),
        SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32),
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(os.path.dirname(app.config['DATABASE']) or '.', exist_ok=True)
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    from services import users, assets, incidents, threats, logs, reports
    from services import vulnerabilities, notifications, playbooks
    for module in (users, assets, incidents, threats, logs, reports,
                   vulnerabilities, notifications, playbooks):
        module.register(app)

    if service:
        @app.before_request
        def limit_service():
            if request.path == '/health':
                return
            parts = request.path.strip('/').split('/')
            group = parts[1] if len(parts) > 1 else ''
            if group == 'actions':
                group = 'playbooks'
            if group != service or parts[0] != OWNERS.get(group):
                abort(404)

    @app.errorhandler(HTTPException)
    def http_error(err):
        return jsonify(status='error', message=err.description), err.code

    @app.errorhandler(sqlite3.IntegrityError)
    def db_error(err):
        return jsonify(status='error', message='Record conflicts with an existing record or a required relationship'), 409

    @app.get('/health')
    def health():
        return {'status': 'ok'}

    return app


if __name__ == '__main__':
    create_app().run(debug=False, port=5000)
