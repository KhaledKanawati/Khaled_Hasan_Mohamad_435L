"""Build repeatable, detailed cases for the assignment's execution evidence."""
import json
from pathlib import Path
from build_postman import req, samples

ROOT = Path(__file__).resolve().parents[1]
K, H, M = '/Khaled_Kanawati', '/Hasan_Zuelghina', '/Mohamad_Zuelghina'
folders = []


def group(name):
    items = []
    folders.append({'name': name, 'item': items})
    return items


def add(items, name, method, path, data=None, role='admin', status=200, save=None):
    item = req(name, method, path, data, role + 'Token' if role else None,
               note=f'{name}. Expected HTTP {status}. Run in order; saved IDs refer only to this evidence run.',
               expected=status)
    if save:
        key, field = save
        item['event'][0]['script']['exec'].append(
            f'if (pm.response.code < 300) pm.environment.set("{key}", pm.response.json().{field});')
    items.append(item)


def main():
    items = group('0 Authentication')
    for role in ('admin', 'analyst', 'employee', 'auditor'):
        add(items, 'Login ' + role, 'POST', K + '/users/login',
            {'username': role, 'password': 'DemoPass123!'}, None, save=(role+'Token','token'))
    add(items, 'Invalid password', 'POST', K+'/users/login', {'username':'admin','password':'incorrect'}, None, 401)
    add(items, 'Missing bearer token', 'GET', H+'/assets', role=None, status=401)

    items = group('1 Users — Khaled Kanawati')
    user = {**samples['register_user'], 'username':'evidence_{{runTag}}', 'email':'evidence_{{runTag}}@example.test'}
    add(items,'Registration success','POST',K+'/users/register',user,None,201,('eUserId','id'))
    add(items,'Duplicate username','POST',K+'/users/register',user,None,409)
    add(items,'Invalid email','POST',K+'/users/register',{**user,'email':'bad-email'},None,400)
    add(items,'Weak password','POST',K+'/users/register',{**user,'password':'weak'},None,400)
    add(items,'All users','GET',K+'/users')
    add(items,'Existing username','GET',K+'/users/evidence_{{runTag}}')
    add(items,'Missing username','GET',K+'/users/no_such_user_{{runTag}}',status=404)
    add(items,'User before update','GET',K+'/users/evidence_{{runTag}}')
    add(items,'Update user','PUT',K+'/users/{{eUserId}}',{'full_name':'Evidence Updated User','department':'Research'})
    add(items,'User after update','GET',K+'/users/evidence_{{runTag}}')
    add(items,'Role catalog as auditor','GET',K+'/users/roles',role='auditor')
    add(items,'Role catalog denied to employee','GET',K+'/users/roles',role='employee',status=403)
    add(items,'Create elevated user','POST',K+'/users',{'full_name':'Role Demo','username':'role_{{runTag}}','email':'role_{{runTag}}@example.test','password':'DemoPass123!','department':'IT','role':'Analyst'},status=201,save=('eRoleId','id'))
    add(items,'View assigned role','GET',K+'/users/{{eRoleId}}/roles',role='auditor')
    add(items,'Revoke role denied','DELETE',K+'/users/{{eRoleId}}/role',role='auditor',status=403)
    add(items,'Revoke elevated role','DELETE',K+'/users/{{eRoleId}}/role')
    add(items,'Verify Employee fallback','GET',K+'/users/{{eRoleId}}/roles')
    add(items,'Create user with no activity','POST',K+'/users',{'full_name':'Empty Record User','username':'empty_{{runTag}}','email':'empty_{{runTag}}@example.test','password':'DemoPass123!','department':'IT','role':'Employee'},status=201,save=('eEmptyId','id'))

    items = group('2 Assets — Hasan Zuelghina')
    for n,level in enumerate(('Low','Medium','High','Critical'),11):
        add(items,'Create '+level+' asset','POST',H+'/assets',{**samples['create_asset'],'name':'evidence-'+level.lower(),'ip_address':f'10.20.0.{n}','criticality':level},status=201,save=('eAssetId' if level=='High' else 'eAsset'+level+'Id','id'))
    for field,value in [('ip_address','invalid'),('criticality','Severe')]:
        add(items,'Invalid asset '+field,'POST',H+'/assets',{**samples['create_asset'],field:value},status=400)
    for name,path in [('All assets',''),('One asset','/{{eAssetId}}'),('Asset before update','/{{eAssetId}}')]:
        add(items,name,'GET',H+'/assets'+path)
    add(items,'Missing asset','GET',H+'/assets/999999',status=404)
    for field,value in [('name','evidence'),('type','Server'),('ip_address','10.20.0.13'),('department','IT'),('criticality','High')]:
        add(items,'Asset search '+field,'GET',H+'/assets/search?'+field+'='+value)
    add(items,'Update asset','PUT',H+'/assets/{{eAssetId}}',{'location':'Lab 2','criticality':'Critical'})
    add(items,'Asset after update','GET',H+'/assets/{{eAssetId}}')
    add(items,'Asset list denied','GET',H+'/assets',role='employee',status=403)
    add(items,'Asset list allowed','GET',H+'/assets',role='auditor')

    items = group('3 Incidents — Mohamad Zuelghina')
    for level in ('Low','Medium','High','Critical'):
        add(items,'Report '+level+' incident','POST',M+'/incidents',{'title':level+' evidence incident','description':'Triage demonstration','category':'Account','severity':level,'asset_id':'{{eAssetId}}'},role='employee',status=201,save=('eIncId' if level=='High' else 'eInc'+level+'Id','id'))
    add(items,'Report without known asset','POST',M+'/incidents',{'title':'Unknown affected device','description':'Employee can report before asset identification','category':'Email','severity':'Medium'},role='employee',status=201)
    add(items,'All incidents','GET',M+'/incidents')
    add(items,'Incident detail','GET',M+'/incidents/{{eIncId}}')
    add(items,'Missing incident','GET',M+'/incidents/999999',status=404)
    add(items,'Assignment denied','PUT',M+'/incidents/{{eIncId}}/assign',{'analyst_id':2},role='employee',status=403)
    add(items,'Assign analyst','PUT',M+'/incidents/{{eIncId}}/assign',{'analyst_id':2})
    add(items,'Assigned incident detail','GET',M+'/incidents/{{eIncId}}',role='analyst')
    add(items,'Invalid incident jump','PUT',M+'/incidents/{{eIncId}}/status',{'status':'Closed'},role='analyst',status=400)
    for status in ('Under Investigation','Mitigated','Resolved','Closed'):
        add(items,'Incident to '+status,'PUT',M+'/incidents/{{eIncId}}/status',{'status':status},role='analyst')
    add(items,'Add investigation note','POST',M+'/incidents/{{eIncId}}/notes',{'content':'Verified authentication records and containment.'},role='analyst',status=201)
    add(items,'Incident with linked notes','GET',M+'/incidents/{{eIncId}}')
    for name,payload in [('Missing title',{'description':'Missing title','category':'Account','severity':'High'}),('Invalid severity',{'title':'Bad severity','description':'Bad','category':'Account','severity':'Severe'})]:
        add(items,name,'POST',M+'/incidents',payload,role='employee',status=400)

    items = group('4 Threats — Khaled Kanawati')
    for kind,value,level,key in [('IP Address','2001:db8:{{$randomInt}}::77','High','eThreatIPId'),('Domain','threat-{{runTag}}.example','Critical','eThreatId'),('File Hash','{{runHash}}','Medium','eThreatHashId')]:
        add(items,'Create '+kind+' threat','POST',K+'/threats',{'type':kind,'value':value,'description':'Known test indicator','severity':level,'source':'SOC'},status=201,save=(key,'id'))
    add(items,'Duplicate indicator','POST',K+'/threats',{'type':'Domain','value':'threat-{{runTag}}.example','description':'Duplicate','severity':'High','source':'SOC'},status=409)
    for kind,value in [('IP Address','bad'),('Domain','bad..domain'),('File Hash','xyz')]:
        add(items,'Invalid '+kind,'POST',K+'/threats',{'type':kind,'value':value,'description':'Bad indicator','severity':'High','source':'SOC'},status=400)
    add(items,'All threats','GET',K+'/threats')
    add(items,'Threat before update','GET',K+'/threats/{{eThreatId}}')
    add(items,'Missing threat','GET',K+'/threats/999999',status=404)
    for field,value in [('type','Domain'),('severity','Critical'),('source','SOC'),('value','threat-{{runTag}}')]:
        add(items,'Threat search '+field,'GET',K+'/threats/search?'+field+'='+value)
    add(items,'Update threat','PUT',K+'/threats/{{eThreatId}}',{'description':'Analyst-confirmed indicator','severity':'High'})
    add(items,'Threat after update','GET',K+'/threats/{{eThreatId}}')

    items = group('5 Logs — Hasan Zuelghina')
    for level in ('Information','Warning'):
        add(items,'Create '+level+' log','POST',H+'/logs',{**samples['create_log'],'severity':level},status=201,save=('eLogId','id'))
    for name,path,status in [('All logs','',200),('One log','/{{eLogId}}',200),('Missing log','/999999',404),('Admin logs','/user/1',200),('User with no logs','/user/{{eEmptyId}}',200)]:
        add(items,name,'GET',H+'/logs'+path,status=status)
    for field,value in [('user_id','1'),('created_at','{{runDate}}'),('action','login_failed'),('severity','Warning'),('service','users')]:
        add(items,'Log search '+field,'GET',H+'/logs/search?'+field+'='+value)

    items = group('6 Vulnerabilities — Khaled Kanawati')
    for n,(level,score) in enumerate([('Low',3.1),('Medium',5.6),('High',8.2),('Critical',9.8)]):
        add(items,'Create '+level+' vulnerability','POST',K+'/vulnerabilities',{**samples['create_vulnerability'],'cve':f'CVE-2026-{1000+n}','title':level+' finding','cvss':score,'severity':level,'asset_id':'{{eAssetId}}'},status=201,save=('eVulnId' if level=='High' else 'eVuln'+level+'Id','id'))
    add(items,'All vulnerabilities','GET',K+'/vulnerabilities')
    add(items,'Vulnerability before update','GET',K+'/vulnerabilities/{{eVulnId}}')
    add(items,'Missing vulnerability','GET',K+'/vulnerabilities/999999',status=404)
    add(items,'Invalid vulnerability transition','PUT',K+'/vulnerabilities/{{eVulnId}}',{'status':'Closed'},status=400)
    for status in ('Under Investigation','In Progress','Resolved','Closed'):
        add(items,'Vulnerability to '+status,'PUT',K+'/vulnerabilities/{{eVulnId}}',{'status':status})
    add(items,'Vulnerability after update','GET',K+'/vulnerabilities/{{eVulnId}}')
    for field,value in [('cve','CVE-2026'),('severity','Critical'),('asset_id','{{eAssetId}}'),('status','Open')]:
        add(items,'Vulnerability search '+field,'GET',K+'/vulnerabilities/search?'+field+'='+value)

    items = group('7 Notifications — Hasan Zuelghina')
    for n in (1,2):
        add(items,'Create notification '+str(n),'POST',H+'/notifications',{**samples['create_notification'],'title':'Evidence notice '+str(n)},status=201,save=('eNoticeId','id'))
    for name,path,status in [('User notifications','/user/3',200),('User without notifications','/user/{{eEmptyId}}',200),('Notification unread','/{{eNoticeId}}',200),('Missing notification','/999999',404)]:
        add(items,name,'GET',H+'/notifications'+path,status=status)
    add(items,'Mark notification read','PUT',H+'/notifications/{{eNoticeId}}/read',role='employee')
    add(items,'Notification after read','GET',H+'/notifications/{{eNoticeId}}')
    for field,value in [('user_id','3'),('type','Security%20Alert'),('severity','Medium'),('status','Read')]:
        add(items,'Notification search '+field,'GET',H+'/notifications/search?'+field+'='+value)

    items = group('8 Playbooks — Mohamad Zuelghina')
    for n in (1,2):
        add(items,'Create playbook '+str(n),'POST',M+'/playbooks',{**samples['create_playbook'],'name':'Evidence playbook '+str(n)},status=201,save=('ePlaybookId','id'))
    add(items,'All playbooks','GET',M+'/playbooks')
    add(items,'Missing playbook','GET',M+'/playbooks/999999',status=404)
    for step in (2,1):
        add(items,'Add step '+str(step),'POST',M+'/playbooks/{{ePlaybookId}}/actions',{'description':'Response step '+str(step),'step_no':step},status=201,save=('eActionId','id'))
    add(items,'Playbook actions ordered by step','GET',M+'/playbooks/{{ePlaybookId}}')
    add(items,'Invalid action jump','PUT',M+'/actions/{{eActionId}}/status',{'status':'Completed'},status=400)
    for status in ('In Progress','Completed'):
        add(items,'Action to '+status,'PUT',M+'/actions/{{eActionId}}/status',{'status':status,'assigned_user_id':2},role='analyst')

    items = group('9 Reports — Mohamad Zuelghina')
    for report in ('summary','incidents','assets','threats','vulnerabilities','activity'):
        add(items,'Report '+report,'GET',M+'/reports/'+report)
    add(items,'Analyst denied reports','GET',M+'/reports/summary',role='analyst',status=403)

    items = group('10 Allowed and denied deletes')
    deletes = [('user',K+'/users',{**samples['create_user'],'username':'delete_{{runTag}}','email':'delete_{{runTag}}@example.test'}),
               ('asset',H+'/assets',samples['create_asset']),('threat',K+'/threats',{**samples['create_threat'],'value':'delete-{{runTag}}.example'}),
               ('log',H+'/logs',samples['create_log']),('vulnerability',K+'/vulnerabilities',{**samples['create_vulnerability'],'asset_id':'{{eAssetId}}'}),
               ('notification',H+'/notifications',samples['create_notification']),('playbook',M+'/playbooks',samples['create_playbook'])]
    for kind,path,data in deletes:
        add(items,'Temporary '+kind,'POST',path,data,status=201,save=('eDeleteId','id'))
        add(items,'Denied '+kind+' delete','DELETE',path+'/{{eDeleteId}}',role='auditor',status=403)
        add(items,'Allowed '+kind+' delete','DELETE',path+'/{{eDeleteId}}')

    collection = {'info': {'name':'Sprint I Detailed Evidence', 'schema':'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
        'description':'Detailed assignment cases. Seed demo users and run folders in order. All examples are test-only records.'},
        'event':[{'listen':'prerequest','script':{'type':'text/javascript','exec':[
            'if (pm.info.requestName === "Login admin") { const tag = Date.now().toString(); pm.collectionVariables.set("runTag", tag); pm.collectionVariables.set("runHash", tag.padStart(64,"0")); pm.collectionVariables.set("runDate", new Date().toISOString().slice(0,10)); }']}}],
        'item':folders}
    path=ROOT/'postman'/'Detailed_Evidence.postman_collection.json'
    path.write_text(json.dumps(collection,indent=2),encoding='utf-8')
    print(f'Wrote {sum(len(f["item"]) for f in folders)} detailed cases')


if __name__ == '__main__':
    main()
