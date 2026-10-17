import pytest
from werkzeug.security import generate_password_hash
from app import create_app
from db import many, one, run

K, H, M = '/Khaled_Kanawati', '/Hasan_Zuelghina', '/Mohamad_Zuelghina'


@pytest.fixture
def env(tmp_path):
    app = create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'test.db'), 'SECRET_KEY': 'test-secret'})
    with app.app_context():
        for name, role in [('admin', 'Admin'), ('analyst', 'Analyst'),
                           ('employee', 'Employee'), ('auditor', 'Auditor')]:
            run('INSERT INTO users(full_name,username,email,password_hash,department,role) VALUES(?,?,?,?,?,?)',
                (name.title(), name, name + '@test.local', generate_password_hash('Pass12345'), 'IT', role))
    client = app.test_client()
    tokens = {}
    for name in ('admin', 'analyst', 'employee', 'auditor'):
        r = client.post(K + '/users/login', json={'username': name, 'password': 'Pass12345'})
        tokens[name] = {'Authorization': 'Bearer ' + r.json['token']}
    return app, client, tokens


def call(env, role, method, path, data=None):
    _, client, tokens = env
    return client.open(path, method=method, json=data, headers=tokens[role])


def asset(env):
    return call(env, 'admin', 'POST', H + '/assets', {
        'name': 'mail-01', 'type': 'Server', 'ip_address': '10.0.0.5',
        'department': 'IT', 'owner_id': 1, 'criticality': 'High'}).json


def incident(env):
    a = asset(env)
    return call(env, 'employee', 'POST', M + '/incidents', {
        'title': 'Phishing', 'description': 'Mailbox compromised', 'category': 'Email',
        'severity': 'High', 'asset_id': a['id']}).json


def test_users_and_permissions(env):
    app, client, _ = env
    assert client.post(K + '/users/register', json={
        'full_name': 'New User', 'username': 'new', 'email': 'new@test.local',
        'password': 'Pass12345', 'department': 'IT'}).status_code == 201
    assert client.post(K + '/users/register', json={
        'full_name': 'New User', 'username': 'new', 'email': 'new@test.local',
        'password': 'Pass12345', 'department': 'IT'}).status_code == 409
    assert client.post(K + '/users/login', json={'username': 'new', 'password': 'wrong'}).status_code == 401
    assert call(env, 'employee', 'GET', K + '/users').status_code == 403
    assert call(env, 'auditor', 'GET', K + '/users').status_code == 200
    assert call(env, 'analyst', 'GET', K + '/users/admin').status_code == 403
    assert call(env, 'employee', 'GET', K + '/users/admin').status_code == 403
    assert call(env, 'employee', 'PUT', K + '/users/1', {'full_name': 'Bad'}).status_code == 403
    assert call(env, 'admin', 'PUT', K + '/users/5/role', {'role': 'Analyst'}).status_code == 200
    assert call(env, 'admin', 'PUT', K + '/users/5/status', {'status': 'Suspended'}).status_code == 200
    assert client.post(K + '/users/login', json={'username': 'new', 'password': 'Pass12345'}).status_code == 401
    with app.app_context():
        assert one('SELECT password_hash FROM users WHERE id=5')['password_hash'] != 'Pass12345'
        assert one("SELECT COUNT(*) AS n FROM logs WHERE action='denied'")['n'] >= 3
    assert call(env, 'admin', 'DELETE', K + '/users/5').status_code == 200
    with app.app_context():
        assert one("SELECT actor_name FROM logs WHERE action='user_create' AND description='User #5 created'")['actor_name'] == 'new'


def test_assets_search_and_validation(env):
    a = asset(env)
    assert call(env, 'admin', 'POST', H + '/assets', {
        'name': 'bad', 'type': 'Server', 'ip_address': 'oops', 'department': 'IT',
        'owner_id': 1, 'criticality': 'High'}).status_code == 400
    assert call(env, 'analyst', 'GET', H + '/assets').status_code == 403
    assert call(env, 'analyst', 'GET', H + '/assets/search?name=mail').json[0]['id'] == a['id']
    assert call(env, 'admin', 'PUT', H + f'/assets/{a["id"]}', {'criticality': 'Critical'}).json['criticality'] == 'Critical'
    assert call(env, 'auditor', 'DELETE', H + f'/assets/{a["id"]}').status_code == 403
    assert call(env, 'admin', 'GET', H + f'/assets/{a["id"]}/history').status_code == 200


def test_incident_assignment_lifecycle_and_notes(env):
    item = incident(env)
    path = M + f'/incidents/{item["id"]}'
    assert call(env, 'analyst', 'GET', path).status_code == 403
    assert call(env, 'employee', 'PUT', path + '/assign', {'analyst_id': 2}).status_code == 403
    assert call(env, 'admin', 'PUT', path + '/assign', {'analyst_id': 3}).status_code == 400
    assert call(env, 'admin', 'PUT', path + '/assign', {'analyst_id': 2}).status_code == 200
    assert call(env, 'analyst', 'GET', path).status_code == 200
    assert call(env, 'analyst', 'PUT', path + '/status', {'status': 'Closed'}).status_code == 400
    for status in ('Under Investigation', 'Mitigated', 'Resolved', 'Closed'):
        assert call(env, 'analyst', 'PUT', path + '/status', {'status': status}).json['status'] == status
    assert call(env, 'analyst', 'POST', path + '/notes', {'content': 'Checked mail logs'}).status_code == 201
    assert len(call(env, 'admin', 'GET', path).json['notes']) == 1


def test_threats_uniqueness_and_filters(env):
    data = {'type': 'IP Address', 'value': '192.0.2.5', 'description': 'Scanner',
            'severity': 'High', 'source': 'SOC'}
    r = call(env, 'admin', 'POST', K + '/threats', data)
    assert r.status_code == 201
    assert call(env, 'admin', 'POST', K + '/threats', data).status_code == 409
    assert call(env, 'analyst', 'GET', K + '/threats/search?severity=High').json[0]['id'] == r.json['id']
    assert call(env, 'admin', 'PUT', K + f'/threats/{r.json["id"]}', {'severity': 'Critical'}).status_code == 200
    assert call(env, 'analyst', 'DELETE', K + f'/threats/{r.json["id"]}').status_code == 403


def test_critical_threat_alert_and_missing_auth(env):
    app, client, _ = env
    assert client.get(K + '/threats').status_code == 401
    with app.app_context():
        assert one("SELECT COUNT(*) AS n FROM logs WHERE action='denied'")['n'] == 1
    r = call(env, 'admin', 'POST', K + '/threats', {
        'type': 'Domain', 'value': 'bad.example', 'description': 'Phishing',
        'severity': 'Critical', 'source': 'SOC'})
    assert r.status_code == 201
    notices = call(env, 'analyst', 'GET', H + '/notifications/user/2').json
    assert notices[0]['type'] == 'Threat Alert'


def test_audit_and_reports(env):
    asset(env)
    call(env, 'employee', 'GET', H + '/assets')
    assert call(env, 'auditor', 'GET', H + '/logs').status_code == 200
    assert call(env, 'auditor', 'GET', H + '/logs/search?action=denied').json
    assert call(env, 'analyst', 'DELETE', H + '/logs/1').status_code == 403
    assert call(env, 'admin', 'GET', M + '/reports/summary').json['assets'] == 1
    for report in ('incidents', 'assets', 'threats', 'vulnerabilities', 'activity'):
        assert call(env, 'auditor', 'GET', M + '/reports/' + report).status_code == 200
    assert call(env, 'employee', 'GET', M + '/reports/summary').status_code == 403


def test_vulnerability_flow(env):
    a = asset(env)
    data = {'title': 'Old package', 'description': 'Patch needed', 'cve': 'CVE-2025-1234',
            'cvss': 8.1, 'severity': 'High', 'asset_id': a['id'], 'source': 'Scanner'}
    r = call(env, 'admin', 'POST', K + '/vulnerabilities', data)
    assert r.status_code == 201
    path = K + f'/vulnerabilities/{r.json["id"]}'
    assert call(env, 'analyst', 'PUT', path, {'status': 'Closed'}).status_code == 400
    for status in ('Under Investigation', 'In Progress', 'Resolved', 'Closed'):
        assert call(env, 'analyst', 'PUT', path, {'status': status}).json['status'] == status
    assert call(env, 'auditor', 'GET', K + '/vulnerabilities/search?asset_id=1').status_code == 200
    assert call(env, 'analyst', 'DELETE', path).status_code == 403


def test_critical_vulnerability_alert_and_bad_cvss(env):
    a = asset(env)
    data = {'title': 'Exposed admin', 'description': 'Patch needed', 'cve': 'CVE-2025-1234', 'cvss': 'bad',
            'severity': 'Critical', 'asset_id': a['id'], 'source': 'Scanner'}
    assert call(env, 'admin', 'POST', K + '/vulnerabilities', data).status_code == 400
    data['cvss'] = 9.8
    assert call(env, 'admin', 'POST', K + '/vulnerabilities', data).status_code == 201
    notices = call(env, 'analyst', 'GET', H + '/notifications/user/2').json
    assert notices[0]['type'] == 'Vulnerability Alert'


def test_notifications_are_private(env):
    r = call(env, 'admin', 'POST', H + '/notifications', {
        'user_id': 3, 'title': 'Update', 'message': 'Review your device',
        'type': 'Security Alert', 'severity': 'Medium'})
    assert r.status_code == 201
    path = H + f'/notifications/{r.json["id"]}'
    assert call(env, 'analyst', 'GET', path).status_code == 403
    assert call(env, 'employee', 'PUT', path + '/read').json['status'] == 'Read'
    assert call(env, 'auditor', 'PUT', path + '/read').status_code == 403
    assert len(call(env, 'employee', 'GET', H + '/notifications/user/3').json) == 1
    assert call(env, 'analyst', 'GET', H + '/notifications/search?status=Read').json == []


def test_playbook_order_and_history(env):
    r = call(env, 'admin', 'POST', M + '/playbooks', {
        'name': 'Phishing response', 'description': 'Contain mailbox',
        'category': 'Email', 'severity': 'High'})
    assert r.status_code == 201
    path = M + f'/playbooks/{r.json["id"]}'
    a = call(env, 'analyst', 'POST', path + '/actions', {'description': 'Disable account', 'step_no': 1})
    assert a.status_code == 201
    assert call(env, 'analyst', 'POST', path + '/actions', {'description': 'Duplicate', 'step_no': 1}).status_code == 409
    action = M + f'/actions/{a.json["id"]}/status'
    assert call(env, 'analyst', 'PUT', action, {'status': 'Completed'}).status_code == 400
    assert call(env, 'analyst', 'PUT', action, {'status': 'In Progress', 'assigned_user_id': 2}).status_code == 200
    assert len(call(env, 'analyst', 'PUT', action, {'status': 'Completed'}).json['history']) == 2
    assert call(env, 'auditor', 'GET', path).json['actions'][0]['status'] == 'Completed'
    assert call(env, 'auditor', 'DELETE', path).status_code == 403


def test_service_process_exposes_only_its_routes(tmp_path):
    app = create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'isolated.db')}, service='assets')
    client = app.test_client()
    assert client.get('/health').status_code == 200
    assert client.get(K + '/users').status_code == 404
    assert client.get(H + '/assets').status_code == 401


def test_wrong_json_types_return_validation_errors(env):
    _, client, _ = env
    bad_requests = [
        ('POST', K + '/users/register', {'full_name': 'New User', 'username': 'new',
                                       'email': 123, 'password': 'Pass12345', 'department': 'IT'}),
        ('POST', K + '/users/login', {'username': 'admin', 'password': 123}),
        ('POST', H + '/assets', {'name': 'bad', 'type': 'Server', 'ip_address': 123,
                               'department': 'IT', 'owner_id': 1, 'criticality': 'High'}),
        ('POST', H + '/assets', {'name': 'bad', 'type': 'Server', 'ip_address': '10.0.0.5',
                               'department': 'IT', 'owner_id': '²', 'criticality': 'High'}),
        ('POST', M + '/incidents', {'title': 'Bad', 'description': 'Bad asset',
                                  'category': 'Email', 'severity': 'High', 'asset_id': [1]}),
        ('POST', K + '/threats', {'type': 'Domain', 'value': 123, 'description': 'Bad',
                                'severity': 'High', 'source': 'SOC'}),
        ('POST', H + '/logs', {'user_id': 1, 'action': 'review', 'description': 'Bad',
                             'severity': 'Warning', 'service': ['logs']}),
        ('POST', K + '/vulnerabilities', {'title': 'Bad', 'description': 'Bad CVSS',
                                        'cve': 'CVE-2025-1234', 'cvss': True, 'severity': 'High', 'asset_id': 1,
                                        'source': 'Scanner'}),
        ('POST', H + '/notifications', {'user_id': 2, 'title': 123, 'message': 'Bad',
                                      'type': 'Security Alert', 'severity': 'High'}),
    ]
    for method, path, data in bad_requests:
        response = client.open(path, method=method, json=data, headers=env[2]['admin'])
        assert response.status_code == 400, (path, response.json)
        assert response.json['status'] == 'error'

    playbook = call(env, 'admin', 'POST', M + '/playbooks', {
        'name': 'Bad step test', 'description': 'Check step validation',
        'category': 'Email', 'severity': 'High'}).json
    response = call(env, 'admin', 'POST', M + f'/playbooks/{playbook["id"]}/actions',
                    {'description': 'Fractional step', 'step_no': 1.5})
    assert response.status_code == 400


def test_required_relationships_domains_and_large_ids(env):
    a = asset(env)
    response = call(env, 'employee', 'POST', M + '/incidents', {
        'title': 'Phishing', 'description': 'Bad email', 'category': 'Email', 'severity': 'High'})
    assert response.status_code == 400
    assert 'asset_id' in response.json['message']
    response = call(env, 'admin', 'POST', K + '/vulnerabilities', {
        'title': 'Old package', 'description': 'Patch needed', 'cvss': 8.1,
        'severity': 'High', 'asset_id': a['id'], 'source': 'Scanner'})
    assert response.status_code == 400
    assert 'cve' in response.json['message']
    for domain in ('-bad.example', 'bad-.example', 'bad..example', 'a' * 64 + '.example'):
        response = call(env, 'admin', 'POST', K + '/threats', {
            'type': 'Domain', 'value': domain, 'description': 'Bad domain',
            'severity': 'High', 'source': 'SOC'})
        assert response.status_code == 400, domain
    for path in (H + '/assets/', M + '/incidents/', K + '/threats/', H + '/logs/',
                 K + '/vulnerabilities/', H + '/notifications/', M + '/playbooks/'):
        response = call(env, 'admin', 'GET', path + '9' * 30)
        assert response.status_code == 400, path
        assert response.json['status'] == 'error'


def test_search_filters_keep_ids_ips_and_read_status_distinct(env):
    a = asset(env)
    with env[0].app_context():
        run('INSERT INTO users(id,full_name,username,email,password_hash,department,role) VALUES(?,?,?,?,?,?,?)',
            (11, 'User Eleven', 'eleven', 'eleven@test.local',
             one('SELECT password_hash FROM users WHERE id=3')['password_hash'], 'IT', 'Employee'))
        run('INSERT INTO assets(id,name,type,ip_address,owner_id,department,criticality) VALUES(?,?,?,?,?,?,?)',
            (11, 'mail-11', 'Server', '10.0.0.50', 1, 'IT', 'High'))
    found = call(env, 'analyst', 'GET', H + '/assets/search?ip_address=10.0.0.5').json
    assert [item['id'] for item in found] == [a['id']]
    for asset_id in (a['id'], 11):
        assert call(env, 'admin', 'POST', K + '/vulnerabilities', {
            'title': 'Old package', 'description': 'Patch needed', 'cve': 'CVE-2026-1234',
            'cvss': 8.1, 'severity': 'High', 'asset_id': asset_id, 'source': 'Scanner'}).status_code == 201
    found = call(env, 'analyst', 'GET', K + f'/vulnerabilities/search?asset_id={a["id"]}').json
    assert len(found) == 1 and found[0]['asset_id'] == a['id']
    call(env, 'admin', 'POST', H + '/logs', {'user_id': 11, 'action': 'review',
        'description': 'Reviewed asset', 'severity': 'Information', 'service': 'assets'})
    found = call(env, 'auditor', 'GET', H + '/logs/search?user_id=1').json
    assert found and all(item['user_id'] == 1 for item in found)
    notices = []
    for user_id in (3, 3, 11):
        notices.append(call(env, 'admin', 'POST', H + '/notifications', {
            'user_id': user_id, 'title': 'Update', 'message': 'Review device',
            'type': 'Security Alert', 'severity': 'Medium'}).json)
    call(env, 'employee', 'PUT', H + f'/notifications/{notices[0]["id"]}/read')
    found = call(env, 'admin', 'GET', H + '/notifications/search?status=Read').json
    assert [item['id'] for item in found] == [notices[0]['id']]
    assert call(env, 'admin', 'GET', H + '/notifications/search?user_id=1').json == []
    assert call(env, 'admin', 'GET', H + '/notifications/search?user_id=invalid').status_code == 400


def test_distributed_report_calls_service_apis(env, monkeypatch):
    from services import reports
    app, _, _ = env
    seen = []
    records = {'users':[{'id':1}], 'assets':[{'id':1}], 'logs':[],
               'incidents':[{'id':1,'status':'Open'}],
               'threats':[{'id':1,'severity':'Critical'}],
               'vulnerabilities':[]}

    def fake_call(group, path):
        seen.append(group)
        return records[group]

    monkeypatch.setattr(reports, 'service_call', fake_call)
    app.config['SERVICE_URLS'] = {key:'http://localhost' for key in records}
    result = call(env, 'admin', 'GET', M + '/reports/summary')
    assert result.json == {'users':1,'assets':1,'open_incidents':1,'critical_threats':1,
                           'vulnerabilities':0,'recent_activity':[]}
    assert set(seen) == set(records)


def test_service_apps_share_notifications_and_reports(tmp_path, monkeypatch):
    import common
    from flask import request
    from services import reports

    groups = ('users', 'assets', 'incidents', 'threats', 'logs', 'reports',
              'vulnerabilities', 'notifications', 'playbooks')
    config = {'TESTING': True, 'DATABASE': str(tmp_path / 'services.db'),
              'SECRET_KEY': 'shared-test-secret',
              'SERVICE_URLS': {name: 'http://localhost' for name in groups}}
    apps = {name: create_app(config, service=name) for name in groups}
    clients = {name: app.test_client() for name, app in apps.items()}
    with apps['users'].app_context():
        for name, role in (('admin', 'Admin'), ('analyst', 'Analyst'),
                           ('employee', 'Employee'), ('auditor', 'Auditor')):
            run('INSERT INTO users(full_name,username,email,password_hash,department,role) VALUES(?,?,?,?,?,?)',
                (name.title(), name, name + '@test.local', generate_password_hash('Pass12345'), 'IT', role))
    headers = {}
    for name in ('admin', 'analyst', 'employee', 'auditor'):
        response = clients['users'].post(K + '/users/login',
                                         json={'username': name, 'password': 'Pass12345'})
        headers[name] = {'Authorization': 'Bearer ' + response.json['token']}

    def local_call(group, path, data=None):
        response = clients[group].open(path, method='POST' if data is not None else 'GET',
                                       json=data, headers={'Authorization': request.headers['Authorization']})
        assert response.status_code < 400, (group, path, response.json)
        return response.json

    monkeypatch.setattr(common, 'service_call', local_call)
    monkeypatch.setattr(reports, 'service_call', local_call)
    asset = clients['assets'].post(H + '/assets', json={
        'name': 'mail-01', 'type': 'Server', 'ip_address': '10.0.0.5',
        'department': 'IT', 'owner_id': 1, 'criticality': 'High'}, headers=headers['admin'])
    assert asset.status_code == 201
    incident = clients['incidents'].post(M + '/incidents', json={
        'title': 'Phishing', 'description': 'Mailbox compromised', 'category': 'Email',
        'severity': 'High', 'asset_id': asset.json['id']}, headers=headers['employee'])
    assert incident.status_code == 201
    assigned = clients['incidents'].put(M + f'/incidents/{incident.json["id"]}/assign',
                                        json={'analyst_id': 2}, headers=headers['admin'])
    assert assigned.status_code == 200
    threat = clients['threats'].post(K + '/threats', json={
        'type': 'Domain', 'value': 'bad.example', 'description': 'Phishing',
        'severity': 'Critical', 'source': 'SOC'}, headers=headers['admin'])
    assert threat.status_code == 201
    vulnerability = clients['vulnerabilities'].post(K + '/vulnerabilities', json={
        'title': 'Old package', 'description': 'Patch needed', 'cve': 'CVE-2025-1234', 'cvss': 9.1,
        'severity': 'Critical', 'asset_id': asset.json['id'], 'source': 'Scanner'},
        headers=headers['admin'])
    assert vulnerability.status_code == 201
    notices = clients['notifications'].get(H + '/notifications/user/2', headers=headers['analyst'])
    assert {item['type'] for item in notices.json} == {
        'Incident Assignment', 'Threat Alert', 'Vulnerability Alert'}
    summary = clients['reports'].get(M + '/reports/summary', headers=headers['auditor'])
    assert summary.status_code == 200
    assert summary.json['assets'] == 1
    assert summary.json['critical_threats'] == 1
    assert summary.json['vulnerabilities'] == 1
    assert clients['logs'].get(H + '/logs', headers=headers['auditor']).status_code == 200
    assert clients['playbooks'].get(M + '/playbooks', headers=headers['auditor']).status_code == 200
