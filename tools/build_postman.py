"""Build the collection from the routes so the import stays in sync with the API."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import create_app

groups = [('Users', 'Khaled_Kanawati', 'users'), ('Assets', 'Hasan_Zuelghina', 'assets'),
          ('Incidents', 'Mohamad_Zuelghina', 'incidents'), ('Threats', 'Khaled_Kanawati', 'threats'),
          ('Audit logs', 'Hasan_Zuelghina', 'logs'), ('Reports', 'Mohamad_Zuelghina', 'reports'),
          ('Vulnerabilities', 'Khaled_Kanawati', 'vulnerabilities'),
          ('Notifications', 'Hasan_Zuelghina', 'notifications'),
          ('Playbooks', 'Mohamad_Zuelghina', 'playbooks')]
samples = {
 'register_user': {'full_name':'New Employee','username':'new_employee_{{$randomInt}}','email':'new_employee_{{$randomInt}}@example.test','password':'DemoPass123!','department':'IT'},
 'create_user': {'full_name':'New Analyst','username':'new_analyst_{{$randomInt}}','email':'new_analyst_{{$randomInt}}@example.test','password':'DemoPass123!','department':'Security','role':'Analyst'},
 'login': {'username':'admin','password':'DemoPass123!'},
 'update_user': {'full_name':'Updated Analyst','email':'analyst_updated_{{$randomInt}}@example.test','department':'IT'},
 'user_role': {'role':'Analyst'}, 'user_status': {'status':'Inactive'},
 'create_asset': {'name':'web-01','type':'Server','ip_address':'10.0.0.10','department':'IT','owner_id':1,'criticality':'High','status':'Active','location':'HQ'},
 'update_asset': {'criticality':'Critical','status':'Under Maintenance'},
 'create_incident': {'title':'Suspicious login','description':'Unexpected login attempt','category':'Account','severity':'High','reporter_id':3,'asset_id':'{{assetId}}'},
 'assign_incident': {'analyst_id':2}, 'incident_status': {'status':'Under Investigation'},
 'add_note': {'content':'Reviewed authentication records'},
 'create_threat': {'type':'Domain','value':'scanner-{{$randomInt}}.example','description':'Known scanner','severity':'High','source':'SOC'},
 'update_threat': {'description':'Confirmed scanner','severity':'Critical','source':'SOC'},
 'create_log': {'user_id':1,'action':'manual_review','description':'Reviewed security dashboard','severity':'Information','service':'reports'},
 'create_vulnerability': {'title':'Unpatched service','description':'Update package','cve':'CVE-2025-1234','cvss':8.2,'severity':'High','asset_id':'{{assetId}}','source':'Scanner'},
 'update_vulnerability': {'status':'Under Investigation','description':'Assigned for review'},
 'create_notification': {'user_id':3,'title':'Security update','message':'Review your device','type':'Security Alert','severity':'Medium'},
 'create_playbook': {'name':'Account compromise','description':'Contain affected account','category':'Account','severity':'High'},
 'create_action': {'description':'Disable account','step_no':1},
 'action_status': {'status':'In Progress','assigned_user_id':2},
}
ids = {'users':'userId','assets':'assetId','incidents':'incidentId','threats':'threatId',
       'logs':'logId','vulnerabilities':'vulnerabilityId','notifications':'notificationId',
       'playbooks':'playbookId','actions':'actionId'}


def req(name, method, path, data=None, token='adminToken', save=None, note=None, expected=None):
    headers = [{'key':'Content-Type','value':'application/json'}]
    if token:
        headers.append({'key':'Authorization','value':'Bearer {{' + token + '}}'})
    request = {'name': name, 'request': {'method':method, 'header':headers,
               'url':'{{baseUrl}}' + path,
               'description': note or f'{method} {path}. Uses the local SQLite database; errors return status and message.'}}
    if data is not None:
        request['request']['body'] = {'mode':'raw','raw':json.dumps(data, indent=2),
                                      'options':{'raw':{'language':'json'}}}
    expected = expected or (201 if method == 'POST' and name != 'Login' else 200)
    checks = [f'pm.test("HTTP {expected}", () => pm.response.to.have.status({expected}));']
    if save:
        checks += ['if (pm.response.code < 300) {',
                   f'  pm.environment.set("{save}", pm.response.json().id);', '}']
    request['event'] = [{'listen':'test','script':{'type':'text/javascript','exec':checks}}]
    return request


def main():
    app = create_app()
    folder_map = {key: [] for _, _, key in groups}
    docs_map = {key: [] for _, _, key in groups}
    for rule in app.url_map.iter_rules():
        path = rule.rule
        if path == '/health': continue
        group = path.split('/')[2]
        if group == 'actions': group = 'playbooks'
        if group not in folder_map: continue
        path = path.replace('<username>', '{{username}}')
        user_var = 'adminId' if group == 'logs' else ('employeeId' if group == 'notifications' else 'userId')
        path = path.replace('<int:user_id>', '{{' + user_var + '}}')
        path = path.replace('<int:id>', '{{' + ids.get(path.split('/')[2], 'actionId') + '}}')
        for method in sorted(rule.methods & {'GET','POST','PUT','DELETE'}):
            name = rule.endpoint.replace('_', ' ').title()
            token = None if rule.endpoint in ('register_user','login') else 'adminToken'
            save = ids.get(group) if rule.endpoint.startswith('create_') else None
            if rule.endpoint == 'create_action': save = 'actionId'
            item = req(name, method, path, samples.get(rule.endpoint) if method in ('POST','PUT') else None,
                       token, save)
            docs_map[group].append(item)
            if method != 'DELETE':
                folder_map[group].append(item)

    # Login requests save tokens for the role-specific evidence calls.
    auth_items = []
    for role in ('admin','analyst','employee','auditor'):
        item = req('Login ' + role.title(), 'POST', '/Khaled_Kanawati/users/login',
                   {'username':role,'password':'DemoPass123!'}, token=None)
        item['event'] = [{'listen':'test','script':{'type':'text/javascript','exec':[
            'pm.test("Login succeeded", () => pm.response.to.have.status(200));',
            f'if (pm.response.code === 200) pm.environment.set("{role}Token", pm.response.json().token);']}}]
        auth_items.append(item)

    evidence = [
        req('Employee denied asset list', 'GET', '/Hasan_Zuelghina/assets', token='employeeToken',
            note='Expected 403; screenshot this response and the request headers.', expected=403),
        req('Auditor allowed asset list', 'GET', '/Hasan_Zuelghina/assets', token='auditorToken',
            note='Expected 200; compare with the denied request.'),
        req('Invalid IP rejected', 'POST', '/Hasan_Zuelghina/assets',
            {**samples['create_asset'], 'ip_address':'invalid'}, note='Expected 400 validation error.', expected=400),
        req('Invalid incident transition rejected', 'PUT', '/Mohamad_Zuelghina/incidents/{{incidentId}}/status',
            {'status':'Closed'}, note='Expected 400 for a skipped lifecycle state.', expected=400),
        req('Bad password rejected', 'POST', '/Khaled_Kanawati/users/login',
            {'username':'admin','password':'incorrect'}, token=None, note='Expected 401 and a failed-login audit record.', expected=401),
        req('Unknown asset ID', 'GET', '/Hasan_Zuelghina/assets/999999', note='Expected 404.', expected=404),
    ]
    cleanup = [
        req('Create user for deletion', 'POST', '/Khaled_Kanawati/users',
            {'full_name':'Temporary User','username':'delete_user_{{$randomInt}}','email':'delete_user_{{$randomInt}}@example.test',
             'password':'DemoPass123!','department':'IT','role':'Employee'}, save='deleteUserId'),
        req('Delete user', 'DELETE', '/Khaled_Kanawati/users/{{deleteUserId}}'),
        req('Create asset for deletion', 'POST', '/Hasan_Zuelghina/assets',
            {**samples['create_asset'], 'name':'temporary-asset', 'ip_address':'10.0.0.201'}, save='deleteAssetId'),
        req('Delete asset', 'DELETE', '/Hasan_Zuelghina/assets/{{deleteAssetId}}'),
        req('Create threat for deletion', 'POST', '/Khaled_Kanawati/threats',
            {**samples['create_threat'], 'value':'delete-{{$randomInt}}.example'}, save='deleteThreatId'),
        req('Delete threat', 'DELETE', '/Khaled_Kanawati/threats/{{deleteThreatId}}'),
        req('Create log for deletion', 'POST', '/Hasan_Zuelghina/logs', samples['create_log'], save='deleteLogId'),
        req('Delete log', 'DELETE', '/Hasan_Zuelghina/logs/{{deleteLogId}}'),
        req('Create vulnerability for deletion', 'POST', '/Khaled_Kanawati/vulnerabilities',
            samples['create_vulnerability'], save='deleteVulnerabilityId'),
        req('Delete vulnerability', 'DELETE', '/Khaled_Kanawati/vulnerabilities/{{deleteVulnerabilityId}}'),
        req('Create notification for deletion', 'POST', '/Hasan_Zuelghina/notifications',
            samples['create_notification'], save='deleteNotificationId'),
        req('Delete notification', 'DELETE', '/Hasan_Zuelghina/notifications/{{deleteNotificationId}}'),
        req('Create playbook for deletion', 'POST', '/Mohamad_Zuelghina/playbooks',
            samples['create_playbook'], save='deletePlaybookId'),
        req('Delete playbook', 'DELETE', '/Mohamad_Zuelghina/playbooks/{{deletePlaybookId}}'),
    ]
    folders = [{'name':'0 Login','item':auth_items}]
    for i, (name, owner, key) in enumerate(groups, 1):
        folders.append({'name':f'{i} {name} ({owner.replace("_", " ")})', 'item':folder_map[key]})
    folders.append({'name':'Evidence checks','item':evidence})
    folders.append({'name':'Delete demos','item':cleanup})
    collection = {'info':{'name':'Security Incident Backend Sprint I',
        '_postman_id':'6f9089fd-ec5d-4db1-a602-48c8ed0f94d1',
        'description':'Run python manage.py seed-demo and python serve.py. Select the supplied environment, then run folders in order. Creation requests save IDs and Delete demos removes only temporary records.',
        'schema':'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'},
        'item':folders}
    values = {'baseUrl':'http://127.0.0.1:5000','username':'employee','adminId':'1','employeeId':'3','userId':'3',
              'assetId':'1','incidentId':'1','threatId':'1','logId':'1',
              'vulnerabilityId':'1','notificationId':'1','playbookId':'1','actionId':'1',
              'adminToken':'','analystToken':'','employeeToken':'','auditorToken':''}
    environment = {'name':'Security Incident Backend Local',
                   'values':[{'key':k,'value':v,'type':'default','enabled':True} for k,v in values.items()],
                   '_postman_variable_scope':'environment',
                   '_postman_exported_using':'Security Incident Backend project'}
    out = ROOT / 'postman'
    out.mkdir(exist_ok=True)
    (out / 'Security_Incident_Backend.postman_collection.json').write_text(json.dumps(collection, indent=2), encoding='utf-8')
    (out / 'Local.postman_environment.json').write_text(json.dumps(environment, indent=2), encoding='utf-8')
    docs = ROOT / 'docs'
    docs.mkdir(exist_ok=True)
    lines = ['# API reference', '',
             'Base URL: `http://127.0.0.1:5000`. Each route begins with the full name of the student assigned to that feature.',
             '', 'Send `Authorization: Bearer <token>` for protected calls. Login returns the token. JSON bodies use `Content-Type: application/json`.',
             '', 'Responses are JSON objects for one record or a report, and JSON arrays for lists and searches. New records return HTTP 201.',
             'Errors return `{"status":"error","message":"..."}` with HTTP 400 (validation), 401 (authentication), 403 (permission), 404 (missing record), or 409 (duplicate/relationship conflict).',
             'The collection contains an editable example body for every POST and PUT request.', '']
    for folder in folders[1:10]:
        lines += ['## ' + folder['name'], '', '| API | Method | Endpoint | Request fields | Success |',
                  '| --- | --- | --- | --- | --- |']
        key = groups[int(folder['name'].split()[0]) - 1][2]
        for item in docs_map[key]:
            r = item['request']
            fields = ', '.join(json.loads(r['body']['raw'])) if 'body' in r else 'Query parameters or path ID, if present'
            success = '201 record' if r['method'] == 'POST' and item['name'] != 'Login' else ('200 message' if r['method'] == 'DELETE' else '200 JSON')
            lines.append(f'| {item["name"]} | {r["method"]} | `{r["url"].replace("{{baseUrl}}", "")}` | {fields} | {success} |')
        lines.append('')
    (docs / 'API.md').write_text('\n'.join(lines), encoding='utf-8')
    print(f'Wrote {sum(len(f["item"]) for f in folders)} Postman requests')


if __name__ == '__main__':
    main()
