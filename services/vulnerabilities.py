import re
from common import *
from db import many
K = '/Khaled_Kanawati'
VULN_FLOW = ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    @route(K + '/vulnerabilities', methods=['POST'])
    @auth(ADMIN)
    def create_vulnerability():
        d = body('title', 'description', 'cvss', 'severity', 'asset_id', 'source')
        choice(d['severity'], LEVELS, 'severity')
        ref('assets', d['asset_id'])
        try: cvss = float(d['cvss'])
        except (TypeError, ValueError): fail(400, 'Invalid CVSS score')
        if not 0 <= cvss <= 10: fail(400, 'CVSS must be between 0 and 10')
        d['cvss'] = cvss
        if d.get('cve') and not re.fullmatch(r'CVE-\d{4}-\d{4,}', d['cve']):
            fail(400, 'Invalid CVE identifier')
        item = insert('vulnerabilities', d, ('title', 'description', 'cve', 'cvss', 'severity', 'asset_id', 'source'))
        if d['severity'] == 'Critical':
            for user in many("SELECT id FROM users WHERE role='Analyst' AND status='Active'"):
                notify(user['id'], 'Critical vulnerability', f'Vulnerability #{item["id"]} requires review', 'Vulnerability Alert', 'Critical')
        return item, 201

    @route(K + '/vulnerabilities', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def vulnerabilities():
        return many('SELECT * FROM vulnerabilities ORDER BY id')

    @route(K + '/vulnerabilities/search', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def vulnerability_search():
        return search('vulnerabilities', ('cve', 'severity', 'asset_id', 'status'))

    @route(K + '/vulnerabilities/<int:id>', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def vulnerability(id):
        return ref('vulnerabilities', id)

    @route(K + '/vulnerabilities/<int:id>', methods=['PUT'])
    @auth(ADMIN, ANALYST)
    def update_vulnerability(id):
        old = ref('vulnerabilities', id)
        d = body()
        if 'severity' in d: choice(d['severity'], LEVELS, 'severity')
        if 'status' in d:
            next_status(old['status'], d['status'], VULN_FLOW)
            if d['status'] == 'Resolved': d['resolved_at'] = one('SELECT CURRENT_TIMESTAMP AS t')['t']
        if 'cvss' in d:
            try: d['cvss'] = float(d['cvss'])
            except (TypeError, ValueError): fail(400, 'Invalid CVSS score')
            if not 0 <= d['cvss'] <= 10: fail(400, 'CVSS must be between 0 and 10')
        if 'cve' in d and d['cve'] and not re.fullmatch(r'CVE-\d{4}-\d{4,}', d['cve']):
            fail(400, 'Invalid CVE identifier')
        return update('vulnerabilities', id, d, ('description', 'cve', 'cvss', 'severity', 'status', 'resolved_at'))

    @route(K + '/vulnerabilities/<int:id>', methods=['DELETE'])
    @auth(ADMIN)
    def delete_vulnerability(id):
        return delete('vulnerabilities', id)
