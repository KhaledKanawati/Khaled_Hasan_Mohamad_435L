from flask import g
from common import *
from db import many, run
H = '/Hasan_Zuelghina'
NOTIFICATION_TYPES = ('Incident Assignment', 'Security Alert', 'System Notification', 'Threat Alert', 'Vulnerability Alert')


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    def visible_notification(id):
        item = ref('notifications', id)
        if g.user['role'] in (EMPLOYEE, ANALYST) and item['user_id'] != g.user['id']:
            return None
        return item

    @route(H + '/notifications', methods=['POST'])
    @auth(ADMIN)
    def create_notification():
        d = body('user_id', 'title', 'message', 'type', 'severity')
        ref('users', d['user_id'])
        choice(d['type'], NOTIFICATION_TYPES, 'type')
        choice(d['severity'], LEVELS, 'severity')
        return insert('notifications', d, ('user_id', 'title', 'message', 'type', 'severity')), 201

    @route(H + '/notifications/user/<int:user_id>', methods=['GET'])
    @auth(ADMIN, ANALYST, EMPLOYEE, AUDITOR)
    def user_notifications(user_id):
        ref('users', user_id)
        if g.user['role'] in (ANALYST, EMPLOYEE) and user_id != g.user['id']:
            return deny()
        return many('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC', (user_id,))

    @route(H + '/notifications/search', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def notifications_search():
        records = search('notifications', ('user_id', 'type', 'severity', 'status'),
                         exact=('user_id', 'type', 'severity', 'status'))
        if g.user['role'] == ANALYST:
            return [item for item in records if item['user_id'] == g.user['id']]
        return records

    @route(H + '/notifications/<int:id>', methods=['GET'])
    @auth(ADMIN, ANALYST, EMPLOYEE, AUDITOR)
    def notification(id):
        return visible_notification(id) or deny()

    @route(H + '/notifications/<int:id>/read', methods=['PUT'])
    @auth(ADMIN, ANALYST, EMPLOYEE)
    def read_notification(id):
        if not visible_notification(id): return deny()
        run("UPDATE notifications SET status='Read', read_at=COALESCE(read_at,CURRENT_TIMESTAMP) WHERE id=?", (id,))
        audit('read', f'Notification #{id} read', service='notifications')
        return ref('notifications', id)

    @route(H + '/notifications/<int:id>', methods=['DELETE'])
    @auth(ADMIN)
    def delete_notification(id):
        return delete('notifications', id)
