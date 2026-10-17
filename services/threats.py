import re
from common import *
from db import one, many, run
K = '/Khaled_Kanawati'
THREAT_TYPES = ('IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other Indicators')


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    def threat_check(d):
        if 'type' in d: choice(d['type'], THREAT_TYPES, 'type')
        if 'severity' in d: choice(d['severity'], LEVELS, 'severity')
        kind, value = d.get('type'), d.get('value')
        if kind == 'IP Address' and value: valid_ip(value)
        domain = r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}'
        if kind == 'Domain' and value and not re.fullmatch(domain, value):
            fail(400, 'Invalid domain')
        if kind == 'File Hash' and value and not re.fullmatch(r'(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', value):
            fail(400, 'Invalid file hash')

    @route(K + '/threats', methods=['POST'])
    @auth(ADMIN)
    def create_threat():
        d = body('type', 'value', 'description', 'severity', 'source')
        threat_check(d)
        item = insert('threats', d, ('type', 'value', 'description', 'severity', 'source'))
        if d['severity'] == 'Critical':
            for user in many("SELECT id FROM users WHERE role='Analyst' AND status='Active'"):
                notify(user['id'], 'Critical threat', f'Threat #{item["id"]} requires review', 'Threat Alert', 'Critical')
        return item, 201

    @route(K + '/threats', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def threats():
        return many('SELECT * FROM threats ORDER BY id')

    @route(K + '/threats/search', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def threats_search():
        return search('threats', ('type', 'value', 'severity', 'source'))

    @route(K + '/threats/<int:id>', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def threat(id):
        return ref('threats', id)

    @route(K + '/threats/<int:id>', methods=['PUT'])
    @auth(ADMIN)
    def update_threat(id):
        d = body()
        threat_check(d)
        return update('threats', id, d, ('description', 'severity', 'source'))

    @route(K + '/threats/<int:id>', methods=['DELETE'])
    @auth(ADMIN)
    def delete_threat(id):
        return delete('threats', id)
