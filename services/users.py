import re
from flask import g, request
from werkzeug.security import check_password_hash, generate_password_hash
from common import *
from db import one, many, run
K = '/Khaled_Kanawati'


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    def add_user(d, role):
        valid_email(d['email'])
        if len(d['password']) < 8 or not re.search(r'[A-Za-z]', d['password']) or not re.search(r'\d', d['password']):
            fail(400, 'Password needs 8 characters, a letter, and a number')
        if role not in (ADMIN, ANALYST, EMPLOYEE, AUDITOR):
            fail(400, 'Invalid role')
        id = run('INSERT INTO users(full_name,username,email,password_hash,department,role) VALUES(?,?,?,?,?,?)',
                 (d['full_name'], d['username'], d['email'], generate_password_hash(d['password']), d['department'], role))
        audit('user_create', f'User #{id} created', service='users',
              user_id=getattr(g, 'user', {}).get('id', id))
        return public_user(ref('users', id)), 201

    @route(K + '/users/register', methods=['POST'])
    def register_user():
        d = body('full_name', 'username', 'email', 'password', 'department')
        if d.get('role', EMPLOYEE) != EMPLOYEE:
            audit('denied', 'Self-registration attempted a privileged role', 'Warning', 'users')
            fail(403, 'Self-registration creates Employee accounts only')
        return add_user(d, EMPLOYEE)

    @route(K + '/users', methods=['POST'])
    @auth(ADMIN)
    def create_user():
        d = body('full_name', 'username', 'email', 'password', 'department', 'role')
        return add_user(d, d['role'])

    @route(K + '/users/login', methods=['POST'])
    def login():
        d = body('username', 'password')
        user = one('SELECT * FROM users WHERE username=? OR email=?', (d['username'], d['username']))
        if not user or not check_password_hash(user['password_hash'], d['password']) or user['status'] != 'Active':
            audit('login_failed', 'Failed login attempt', 'Warning', 'users', user['id'] if user else None)
            return api_error(401, 'Invalid credentials or inactive account')
        run('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?', (user['id'],))
        audit('login_success', 'Successful login', service='users', user_id=user['id'])
        return {'token': token_for(user), 'user': public_user(ref('users', user['id']))}

    @route(K + '/users', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def users():
        return [public_user(u) for u in many('SELECT * FROM users ORDER BY id')]

    @route(K + '/users/<username>', methods=['GET'])
    @auth(ADMIN, AUDITOR, EMPLOYEE)
    def user_by_name(username):
        user = one('SELECT * FROM users WHERE username=?', (username,))
        if not user:
            fail(404, 'User not found')
        if g.user['role'] == EMPLOYEE and g.user['id'] != user['id']:
            return deny()
        return public_user(user)

    @route(K + '/users/<int:id>', methods=['PUT'])
    @auth(ADMIN, EMPLOYEE)
    def update_user(id):
        if g.user['role'] == EMPLOYEE and g.user['id'] != id:
            return deny()
        d = body()
        if 'email' in d:
            valid_email(d['email'])
        return public_user(update('users', id, d, ('full_name', 'email', 'department')))

    @route(K + '/users/<int:id>/role', methods=['PUT'])
    @auth(ADMIN)
    def user_role(id):
        d = body('role')
        choice(d['role'], (ADMIN, ANALYST, EMPLOYEE, AUDITOR), 'role')
        result = update('users', id, d, ('role',))
        audit('role_change', f'User #{id} assigned {d["role"]}', service='users')
        return public_user(result)

    @route(K + '/users/<int:id>/status', methods=['PUT'])
    @auth(ADMIN)
    def user_status(id):
        d = body('status')
        choice(d['status'], ('Active', 'Inactive', 'Suspended'), 'status')
        return public_user(update('users', id, d, ('status',)))

    @route(K + '/users/<int:id>', methods=['DELETE'])
    @auth(ADMIN)
    def delete_user(id):
        if g.user['id'] == id:
            fail(400, 'Administrator cannot delete own account')
        return delete('users', id)
