"""Execute a collection over HTTP and save actual request/response evidence."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', default='http://127.0.0.1:5000')
    parser.add_argument('--collection', default='Detailed_Evidence.postman_collection.json')
    parser.add_argument('--database', default=str(ROOT/'data'/'security.db'))
    args = parser.parse_args()
    path = ROOT/'postman'/args.collection
    collection = json.loads(path.read_text(encoding='utf-8'))
    env = json.loads((ROOT/'postman'/'Local.postman_environment.json').read_text(encoding='utf-8'))
    values = {v['key']:str(v['value']) for v in env['values']}
    tag = str(time.time_ns()//1000000)
    values.update(baseUrl=args.base_url, runTag=tag, runHash=tag.zfill(64),
                  runDate=datetime.now(timezone.utc).date().isoformat())
    counter = 1000

    def expand(text):
        nonlocal counter
        while '{{$randomInt}}' in text:
            counter += 1
            text = text.replace('{{$randomInt}}', str(counter), 1)
        return re.sub(r'{{(\w+)}}', lambda m:values[m[1]], text)

    results, comparisons = [], []
    with sqlite3.connect(args.database) as db:
        db.row_factory = sqlite3.Row

        def report_check(url, data):
            if '/reports/' not in url:
                return
            kind=url.rsplit('/',1)[-1]
            rows={t:[dict(r) for r in db.execute('SELECT * FROM '+t)]
                  for t in ('users','assets','incidents','threats','logs','vulnerabilities')}
            expected={}
            if kind=='summary':
                expected={'users':len(rows['users']), 'assets':len(rows['assets']),
                    'open_incidents':sum(r['status']=='Open' for r in rows['incidents']),
                    'critical_threats':sum(r['severity']=='Critical' for r in rows['threats']),
                    'vulnerabilities':len(rows['vulnerabilities'])}
            else:
                table='logs' if kind=='activity' else kind
                expected['total']=len(rows[table])
                if kind in ('incidents','threats','vulnerabilities'):
                    expected['by_severity']=dict(Counter(r['severity'] for r in rows[table]))
                if kind in ('incidents','vulnerabilities'):
                    expected['by_status']=dict(Counter(r['status'] for r in rows[table]))
                if kind in ('assets','threats'):
                    expected['by_type']=dict(Counter(r['type'] for r in rows[table]))
                if kind=='assets': expected['critical']=sum(r['criticality']=='Critical' for r in rows[table])
                if kind=='vulnerabilities': expected['critical']=sum(r['severity']=='Critical' for r in rows[table])
                if kind=='activity':
                    expected.update(login_attempts=sum(r['action'] in ('login_success','login_failed') for r in rows['logs']),
                        failed_logins=sum(r['action']=='login_failed' for r in rows['logs']),
                        by_action=dict(Counter(r['action'] for r in rows['logs'])))
            for key,value in expected.items():
                assert data[key]==value, (kind,key,data[key],value)
            comparisons.append({'report':kind,'expected_from_database':expected,'matched':True})

        for folder in collection['item']:
            for item in folder['item']:
                spec=item['request']
                url=expand(spec['url'])
                headers={h['key']:expand(h['value']) for h in spec['header']}
                payload=expand(spec['body']['raw']) if 'body' in spec else None
                request=Request(url, data=payload.encode() if payload else None, headers=headers, method=spec['method'])
                start=time.perf_counter()
                try:
                    reply=urlopen(request,timeout=20)
                except HTTPError as error:
                    reply=error
                with reply:
                    status=reply.code
                    response=json.loads(reply.read())
                    response_headers=dict(reply.headers)
                scripts='\n'.join(line for event in item.get('event',[]) for line in event['script']['exec'])
                expected=int(re.search(r'status\((\d+)\)',scripts)[1])
                assert status==expected, (folder['name'],item['name'],expected,status,response)
                if status<300:
                    for key,field in re.findall(r'pm.environment.set\("(\w+)", pm.response.json\(\)\.(\w+)\)',scripts):
                        values[key]=str(response[field])
                    report_check(url,response)
                safe_body=dict(response) if isinstance(response,dict) else response
                if isinstance(safe_body,dict) and 'token' in safe_body:
                    safe_body['token']='<redacted demo bearer token>'
                record={'folder':folder['name'],'name':item['name'],'method':spec['method'],
                    'url':url,'request_body':json.loads(payload) if payload else None,
                    'expected_status':expected,'actual_status':status,'passed':True,
                    'response':safe_body,'elapsed_ms':round((time.perf_counter()-start)*1000,2)}
                results.append(record)
                # These examples are actual recorded responses, not invented sample outputs.
                original={**spec,'url':url,'header':[h for h in spec['header'] if h['key']!='Authorization']}
                if payload: original['body']={**spec['body'],'raw':payload}
                item['response']=[{'name':'Recorded local execution '+str(status), 'originalRequest':original,
                    'status':str(status),'code':status,'_postman_previewlanguage':'json',
                    'header':[{'key':k,'value':v} for k,v in response_headers.items()],
                    'cookie':[],'body':json.dumps(safe_body,indent=2)}]

        tables=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        snapshot={t:{'columns':[dict(r) for r in db.execute('PRAGMA table_info('+t+')')],
                      'foreign_keys':[dict(r) for r in db.execute('PRAGMA foreign_key_list('+t+')')],
                      'records':[dict(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY id')]}
                  for t in tables}
    dest=ROOT/'evidence'
    dest.mkdir(exist_ok=True)
    summary={'executed_at_utc':datetime.now(timezone.utc).isoformat(), 'base_url':args.base_url,
             'collection':args.collection,'passed':len(results),'failed':0,
             'report_database_comparisons':comparisons,'results':results}
    (dest/'execution_results.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    (dest/'database_records.json').write_text(json.dumps(snapshot,indent=2),encoding='utf-8')
    path.write_text(json.dumps(collection,indent=2),encoding='utf-8')
    print(f'{len(results)} live HTTP cases passed; {len(comparisons)} reports match the database; {len(tables)} tables recorded.')


if __name__=='__main__':
    main()
