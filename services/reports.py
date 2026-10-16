from flask import current_app
from common import *
from db import many
K = '/Khaled_Kanawati'
H = '/Hasan_Zuelghina'
M = '/Mohamad_Zuelghina'


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    report_paths = {'users': K + '/users', 'assets': H + '/assets',
                    'incidents': M + '/incidents', 'threats': K + '/threats',
                    'logs': H + '/logs', 'vulnerabilities': K + '/vulnerabilities'}

    def rows(table):
        if current_app.config.get('SERVICE_URLS'):
            return service_call(table, report_paths[table])
        return many(f'SELECT * FROM {table} ORDER BY id')

    def grouped(records, field):
        counts = {}
        for record in records:
            value = record[field]
            counts[value] = counts.get(value, 0) + 1
        return counts

    @route(M + '/reports/summary', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def summary():
        incidents, threats = rows('incidents'), rows('threats')
        recent_logs = sorted(rows('logs'), key=lambda x: x['id'], reverse=True)[:5]
        return {'users': len(rows('users')), 'assets': len(rows('assets')),
                'open_incidents': sum(x['status'] == 'Open' for x in incidents),
                'critical_threats': sum(x['severity'] == 'Critical' for x in threats),
                'vulnerabilities': len(rows('vulnerabilities')),
                'recent_activity': recent_logs}

    @route(M + '/reports/incidents', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def incident_report():
        records = rows('incidents')
        return {'total': len(records), 'by_severity': grouped(records, 'severity'),
                'by_status': grouped(records, 'status')}

    @route(M + '/reports/assets', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def asset_report():
        records = rows('assets')
        return {'total': len(records), 'critical': sum(x['criticality'] == 'Critical' for x in records),
                'by_type': grouped(records, 'type')}

    @route(M + '/reports/threats', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def threat_report():
        records = rows('threats')
        return {'total': len(records), 'by_severity': grouped(records, 'severity'),
                'by_type': grouped(records, 'type'),
                'recent': sorted(records, key=lambda x: x['id'], reverse=True)[:5]}

    @route(M + '/reports/vulnerabilities', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def vulnerability_report():
        records = rows('vulnerabilities')
        return {'total': len(records), 'by_severity': grouped(records, 'severity'),
                'by_status': grouped(records, 'status'),
                'critical': sum(x['severity'] == 'Critical' for x in records)}

    @route(M + '/reports/activity', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def activity_report():
        records = rows('logs')
        return {'total': len(records),
                'login_attempts': sum(x['action'] in ('login_success', 'login_failed') for x in records),
                'failed_logins': sum(x['action'] == 'login_failed' for x in records),
                'by_action': grouped(records, 'action')}
