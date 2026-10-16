from flask import g
from common import *
from db import many, run
M = '/Mohamad_Zuelghina'
ACTION_FLOW = ('Pending', 'In Progress', 'Completed')


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    def playbook_view(id):
        item = ref('playbooks', id)
        item['actions'] = many('SELECT * FROM actions WHERE playbook_id=? ORDER BY step_no', (id,))
        return item

    @route(M + '/playbooks', methods=['POST'])
    @auth(ADMIN)
    def create_playbook():
        d = body('name', 'description', 'category', 'severity')
        choice(d['severity'], LEVELS, 'severity')
        d['created_by'] = g.user['id']
        return insert('playbooks', d, ('name', 'description', 'category', 'severity', 'created_by')), 201

    @route(M + '/playbooks', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def playbooks():
        return many('SELECT * FROM playbooks ORDER BY id')

    @route(M + '/playbooks/<int:id>', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def playbook(id):
        return playbook_view(id)

    @route(M + '/playbooks/<int:id>/actions', methods=['POST'])
    @auth(ADMIN, ANALYST)
    def create_action(id):
        ref('playbooks', id)
        d = body('description', 'step_no')
        try: step = int(d['step_no'])
        except (TypeError, ValueError): fail(400, 'Step number must be positive')
        if step < 1: fail(400, 'Step number must be positive')
        action = {'playbook_id': id, 'description': d['description'], 'step_no': step}
        return insert('actions', action, ('playbook_id', 'description', 'step_no')), 201

    @route(M + '/actions/<int:id>/status', methods=['PUT'])
    @auth(ADMIN, ANALYST)
    def action_status(id):
        item = ref('actions', id)
        d = body('status')
        next_status(item['status'], d['status'], ACTION_FLOW)
        assignee = d.get('assigned_user_id', item['assigned_user_id'])
        if assignee:
            user = ref('users', assignee)
            if user['role'] != ANALYST: fail(400, 'Action assignee must be an Analyst')
        run('UPDATE actions SET status=?, assigned_user_id=?, completed_at=CASE WHEN ?="Completed" THEN CURRENT_TIMESTAMP ELSE completed_at END WHERE id=?',
            (d['status'], assignee, d['status'], id))
        run('INSERT INTO action_history(action_id,status,actor_id) VALUES(?,?,?)', (id, d['status'], g.user['id']))
        audit('status', f'Action #{id}: {item["status"]} to {d["status"]}', service='actions')
        result = ref('actions', id)
        result['history'] = many('SELECT * FROM action_history WHERE action_id=? ORDER BY id', (id,))
        return result

    @route(M + '/playbooks/<int:id>', methods=['DELETE'])
    @auth(ADMIN)
    def delete_playbook(id):
        return delete('playbooks', id)
