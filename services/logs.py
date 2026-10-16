from common import *
from db import one, many, run
H = '/Hasan_Zuelghina'
LOG_LEVELS = ('Information', 'Warning', 'Error', 'Critical')


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    @route(H + '/logs', methods=['POST'])
    @auth(ADMIN)
    def create_log():
        d = body('user_id', 'action', 'description', 'severity', 'service')
        choice(d['severity'], LOG_LEVELS, 'severity')
        ref('users', d['user_id'])
        actor = ref('users', d['user_id'])
        id = run('INSERT INTO logs(user_id,actor_name,action,description,severity,service) VALUES(?,?,?,?,?,?)',
                 (d['user_id'], actor['username'], d['action'], d['description'], d['severity'], d['service']))
        return ref('logs', id), 201

    @route(H + '/logs', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def logs():
        return many('SELECT * FROM logs ORDER BY id DESC')

    @route(H + '/logs/search', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def logs_search():
        return search('logs', ('user_id', 'created_at', 'action', 'severity', 'service'))

    @route(H + '/logs/user/<int:user_id>', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def user_logs(user_id):
        ref('users', user_id)
        return many('SELECT * FROM logs WHERE user_id=? ORDER BY id DESC', (user_id,))

    @route(H + '/logs/<int:id>', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def log(id):
        return ref('logs', id)

    @route(H + '/logs/<int:id>', methods=['DELETE'])
    @auth(ADMIN)
    def delete_log(id):
        return delete('logs', id)
