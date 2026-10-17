import ipaddress
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from functools import wraps
from flask import abort, g, jsonify, request, current_app
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from db import one, many, run

ADMIN, ANALYST, EMPLOYEE, AUDITOR = 'Admin', 'Analyst', 'Employee', 'Auditor'
LEVELS = ('Low', 'Medium', 'High', 'Critical')
OWNERS = {'users': 'Khaled_Kanawati', 'assets': 'Hasan_Zuelghina',
          'incidents': 'Mohamad_Zuelghina', 'threats': 'Khaled_Kanawati',
          'logs': 'Hasan_Zuelghina', 'reports': 'Mohamad_Zuelghina',
          'vulnerabilities': 'Khaled_Kanawati', 'notifications': 'Hasan_Zuelghina',
          'playbooks': 'Mohamad_Zuelghina', 'actions': 'Mohamad_Zuelghina'}
TEXT_FIELDS = {'full_name', 'username', 'email', 'password', 'department', 'role',
               'status', 'name', 'type', 'ip_address', 'criticality', 'title',
               'description', 'category', 'severity', 'source', 'content',
               'value', 'action', 'service', 'message'}
OPTIONAL_TEXT_FIELDS = {'operating_system', 'location', 'cve'}
ID_FIELDS = {'user_id', 'owner_id', 'reporter_id', 'asset_id', 'analyst_id',
             'assigned_user_id', 'step_no'}


def api_error(code, message):
    return jsonify(status='error', message=message), code


def fail(code, message):
    abort(code, description=message)


def positive_int(value, field):
    raw = str(value)
    if (isinstance(value, bool) or not isinstance(value, (int, str))
            or not re.fullmatch(r'[0-9]{1,19}', raw)):
        fail(400, f'{field} must be a positive whole number')
    number = int(raw)
    if not 1 <= number <= 2**63 - 1:
        fail(400, f'{field} must be a positive whole number')
    return number


def body(*required):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        fail(400, 'Expected a JSON object')
    missing = [key for key in required if data.get(key) is None or data[key] == '']
    if missing:
        fail(400, 'Missing required fields: ' + ', '.join(missing))
    for key, value in data.items():
        if key in TEXT_FIELDS and (not isinstance(value, str) or not value.strip()):
            fail(400, f'{key} must be non-empty text')
        if key in OPTIONAL_TEXT_FIELDS and value is not None and not isinstance(value, str):
            fail(400, f'{key} must be text')
        if key in ID_FIELDS and value is not None:
            data[key] = positive_int(value, key)
        if key == 'cvss' and isinstance(value, bool):
            fail(400, 'Invalid CVSS score')
    return data


def choice(value, allowed, field):
    if value not in allowed:
        fail(400, f'{field} must be one of: {", ".join(allowed)}')
    return value


def ref(table, id):
    id = positive_int(id, 'id')
    row = one(f'SELECT * FROM {table} WHERE id=?', (id,))
    if not row:
        fail(404, f'{table[:-1].capitalize()} not found')
    return row


def public_user(user):
    return {key: value for key, value in user.items() if key != 'password_hash'}


def token_for(user):
    signer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return signer.dumps(user['id'], salt='login')


def auth(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            header = request.headers.get('Authorization', '')
            if not header.startswith('Bearer '):
                audit('denied', f'Missing token for {request.method} {request.path}', 'Warning', request.path)
                return api_error(401, 'Bearer token required')
            try:
                signer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
                user_id = signer.loads(header[7:], salt='login', max_age=86400)
            except (BadSignature, SignatureExpired):
                audit('denied', f'Invalid token for {request.method} {request.path}', 'Warning', request.path)
                return api_error(401, 'Invalid or expired token')
            user = one('SELECT * FROM users WHERE id=?', (user_id,))
            if not user or user['status'] != 'Active':
                audit('denied', f'Unavailable account for {request.method} {request.path}', 'Warning', request.path,
                      user['id'] if user else None)
                return api_error(401, 'Account is unavailable')
            g.user = user
            if roles and user['role'] not in roles:
                audit('denied', f'{request.method} {request.path}', 'Warning', request.path)
                return api_error(403, 'User does not have permission to perform this operation')
            return fn(*args, **kwargs)
        return wrapped
    return deco


def deny(message='User does not have permission to perform this operation'):
    audit('denied', f'{request.method} {request.path}', 'Warning', request.path)
    return api_error(403, message)


def audit(action, description, severity='Information', service=None, user_id=None):
    if user_id is None:
        user_id = getattr(g, 'user', {}).get('id')
    actor = one('SELECT username FROM users WHERE id=?', (user_id,)) if user_id else None
    run('INSERT INTO logs(user_id,actor_name,action,description,severity,service) VALUES(?,?,?,?,?,?)',
        (user_id, actor['username'] if actor else None, action, description, severity, service or request.path))


def insert(table, data, fields):
    cols = [key for key in fields if key in data]
    sql = f'INSERT INTO {table} ({", ".join(cols)}) VALUES ({", ".join("?" for _ in cols)})'
    id = run(sql, [data[key] for key in cols])
    audit('create', f'{table} #{id} created', service=table)
    return ref(table, id)


def update(table, id, data, fields):
    changes = {key: data[key] for key in fields if key in data}
    if not changes:
        fail(400, 'No update fields provided')
    ref(table, id)
    sql = f'UPDATE {table} SET {", ".join(key + "=?" for key in changes)} WHERE id=?'
    run(sql, list(changes.values()) + [id])
    audit('update', f'{table} #{id} updated', service=table)
    return ref(table, id)


def delete(table, id):
    ref(table, id)
    run(f'DELETE FROM {table} WHERE id=?', (id,))
    audit('delete', f'{table} #{id} deleted', service=table)
    return {'message': f'{table[:-1].capitalize()} deleted'}


def search(table, fields):
    clauses, values = [], []
    for field in fields:
        value = request.args.get(field)
        if value:
            clauses.append(f'CAST({field} AS TEXT) LIKE ?')
            values.append('%' + value + '%')
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    return many(f'SELECT * FROM {table}{where} ORDER BY id', values)


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        fail(400, 'Invalid IP address')


def valid_email(value):
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
        fail(400, 'Invalid email address')


def next_status(old, new, order):
    if old not in order or new not in order or order.index(new) != order.index(old) + 1:
        fail(400, f'Invalid status transition from {old} to {new}')


def service_call(group, path, data=None):
    urls = current_app.config.get('SERVICE_URLS')
    if not urls:
        return None
    headers = {'Authorization': request.headers.get('Authorization', '')}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    outgoing = Request(urls[group] + path,
                       data=json.dumps(data).encode() if data is not None else None,
                       headers=headers, method='POST' if data is not None else 'GET')
    try:
        with urlopen(outgoing, timeout=10) as reply:
            return json.load(reply)
    except (HTTPError, URLError):
        fail(502, f'{group} service is unavailable')


def notify(user_id, title, message, kind, severity):
    data = {'user_id': user_id, 'title': title, 'message': message,
            'type': kind, 'severity': severity}
    if current_app.config.get('SERVICE_URLS'):
        service_call('notifications', '/Hasan_Zuelghina/notifications', data)
    else:
        run('INSERT INTO notifications(user_id,title,message,type,severity) VALUES(?,?,?,?,?)',
            (user_id, title, message, kind, severity))
