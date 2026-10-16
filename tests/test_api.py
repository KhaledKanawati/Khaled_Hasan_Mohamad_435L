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
    data = {'title': 'Exposed admin', 'description': 'Patch needed', 'cvss': 'bad',
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
