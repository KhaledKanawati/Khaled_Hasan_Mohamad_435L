"""Run the importable collection in order against the Flask API."""
import json
import re
import pytest
from datetime import datetime, timezone
from pathlib import Path

from app import create_app
from manage import create_user

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('collection_name', ['Security_Incident_Backend.postman_collection.json',
                                             'Detailed_Evidence.postman_collection.json'])
def test_collection_runs_in_order(tmp_path, collection_name):
    app = create_app({'TESTING': True, 'DATABASE': str(tmp_path / 'postman.db'),
                      'SECRET_KEY': 'collection-test-secret'})
    with app.app_context():
        for name, role in [('admin', 'Admin'), ('analyst', 'Analyst'),
                           ('employee', 'Employee'), ('auditor', 'Auditor')]:
            create_user(name.title(), name, role, 'DemoPass123!')

    collection = json.loads((ROOT / 'postman' / collection_name).read_text(encoding='utf-8'))
    environment = json.loads((ROOT / 'postman' / 'Local.postman_environment.json').read_text())
    values = {item['key']: str(item['value']) for item in environment['values']}
    values.update(runTag='123456789', runHash='0'*55+'123456789',
                  runDate=datetime.now(timezone.utc).date().isoformat())
    counter = 100

    def expand(value):
        nonlocal counter
        while '{{$randomInt}}' in value:
            counter += 1
            value = value.replace('{{$randomInt}}', str(counter), 1)
        return re.sub(r'{{(\w+)}}', lambda match: values[match.group(1)], value)

    client = app.test_client()
    for folder in collection['item']:
        for item in folder['item']:
            spec = item['request']
            path = expand(spec['url']).removeprefix(values['baseUrl'])
            headers = {h['key']: expand(h['value']) for h in spec['header']}
            data = json.loads(expand(spec['body']['raw'])) if 'body' in spec else None
            response = client.open(path, method=spec['method'], json=data, headers=headers)
            scripts = '\n'.join(line for event in item.get('event', []) for line in event['script']['exec'])
            expected = int(re.search(r'status\((\d+)\)', scripts).group(1))
            assert response.status_code == expected, (folder['name'], item['name'], response.json)
            if response.status_code < 300:
                for key, field in re.findall(r'pm.environment.set\("(\w+)", pm.response.json\(\)\.(\w+)\)', scripts):
                    values[key] = str(response.json[field])
