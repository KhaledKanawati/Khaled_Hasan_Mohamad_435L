from flask import g
from common import *
from db import one, many, run
M = '/Mohamad_Zuelghina'
INCIDENT_FLOW = ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    def incident_view(id):
        item = ref('incidents', id)
        item['notes'] = many('SELECT * FROM notes WHERE incident_id=? ORDER BY id', (id,))
        return item

    @route(M + '/incidents', methods=['POST'])
    @auth(ADMIN, EMPLOYEE)
    def create_incident():
        d = body('title', 'description', 'category', 'severity')
        choice(d['severity'], LEVELS, 'severity')
        if g.user['role'] == EMPLOYEE:
            d['reporter_id'] = g.user['id']
        else:
            d['reporter_id'] = d.get('reporter_id', g.user['id'])
            ref('users', d['reporter_id'])
        if d.get('asset_id') is not None:
            ref('assets', d['asset_id'])
        return insert('incidents', d, ('title', 'description', 'category', 'severity', 'reporter_id', 'asset_id')), 201

    @route(M + '/incidents', methods=['GET'])
    @auth(ADMIN, AUDITOR, EMPLOYEE, ANALYST)
    def incidents():
        if g.user['role'] == EMPLOYEE:
            return many('SELECT * FROM incidents WHERE reporter_id=? ORDER BY id', (g.user['id'],))
        if g.user['role'] == ANALYST:
            return many('SELECT * FROM incidents WHERE analyst_id=? ORDER BY id', (g.user['id'],))
        return many('SELECT * FROM incidents ORDER BY id')

    @route(M + '/incidents/<int:id>', methods=['GET'])
    @auth(ADMIN, ANALYST, EMPLOYEE, AUDITOR)
    def incident(id):
        item = incident_view(id)
        if g.user['role'] == EMPLOYEE and item['reporter_id'] != g.user['id']:
            return deny()
        if g.user['role'] == ANALYST and item['analyst_id'] != g.user['id']:
            return deny()
        return item

    @route(M + '/incidents/<int:id>/assign', methods=['PUT'])
    @auth(ADMIN)
    def assign_incident(id):
        ref('incidents', id)
        d = body('analyst_id')
        analyst = ref('users', d['analyst_id'])
        if analyst['role'] != ANALYST:
            fail(400, 'Assigned user must be an Analyst')
        run('UPDATE incidents SET analyst_id=? WHERE id=?', (analyst['id'], id))
        audit('assign', f'Incident #{id} assigned to analyst #{analyst["id"]}', service='incidents')
        notify(analyst['id'], 'Incident assigned', f'Incident #{id} assigned to you', 'Incident Assignment', 'High')
        return incident_view(id)

    @route(M + '/incidents/<int:id>/status', methods=['PUT'])
    @auth(ADMIN, ANALYST)
    def incident_status(id):
        item = ref('incidents', id)
        if g.user['role'] == ANALYST and item['analyst_id'] != g.user['id']:
            return deny()
        d = body('status')
        next_status(item['status'], d['status'], INCIDENT_FLOW)
        run('UPDATE incidents SET status=?, resolved_at=CASE WHEN ?="Resolved" THEN CURRENT_TIMESTAMP ELSE resolved_at END WHERE id=?',
            (d['status'], d['status'], id))
        audit('status', f'Incident #{id}: {item["status"]} to {d["status"]}', service='incidents')
        return incident_view(id)

    @route(M + '/incidents/<int:id>/notes', methods=['POST'])
    @auth(ADMIN, ANALYST)
    def add_note(id):
        item = ref('incidents', id)
        if g.user['role'] == ANALYST and item['analyst_id'] != g.user['id']:
            return deny()
        d = body('content')
        note_id = run('INSERT INTO notes(incident_id,analyst_id,content) VALUES(?,?,?)',
                      (id, g.user['id'], d['content']))
        audit('note', f'Note #{note_id} added to incident #{id}', service='incidents')
        return ref('notes', note_id), 201
