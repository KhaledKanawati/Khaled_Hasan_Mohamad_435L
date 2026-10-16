from common import *
from db import one, many, run
H = '/Hasan_Zuelghina'
ASSET_TYPES = ('Server', 'Workstation', 'Database', 'Application', 'Network Device', 'Cloud Resource')


def register(app):
    def route(path, **opts):
        return app.route(path, **opts)

    @route(H + '/assets', methods=['POST'])
    @auth(ADMIN)
    def create_asset():
        d = body('name', 'type', 'ip_address', 'department', 'owner_id', 'criticality')
        choice(d['type'], ASSET_TYPES, 'type')
        choice(d['criticality'], LEVELS, 'criticality')
        choice(d.get('status', 'Active'), ('Active', 'Inactive', 'Under Maintenance'), 'status')
        valid_ip(d['ip_address'])
        ref('users', d['owner_id'])
        return insert('assets', d, ('name', 'type', 'ip_address', 'operating_system', 'owner_id', 'department', 'location', 'criticality', 'status')), 201

    @route(H + '/assets', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def assets():
        return many('SELECT * FROM assets ORDER BY id')

    @route(H + '/assets/search', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def assets_search():
        return search('assets', ('name', 'type', 'ip_address', 'department', 'criticality'))

    @route(H + '/assets/<int:id>', methods=['GET'])
    @auth(ADMIN, ANALYST, AUDITOR)
    def asset(id):
        return ref('assets', id)

    @route(H + '/assets/<int:id>/history', methods=['GET'])
    @auth(ADMIN, AUDITOR)
    def asset_history(id):
        ref('assets', id)
        return many("SELECT * FROM logs WHERE service='assets' AND description LIKE ? ORDER BY id", (f'%assets #{id} %',))

    @route(H + '/assets/<int:id>', methods=['PUT'])
    @auth(ADMIN)
    def update_asset(id):
        d = body()
        if 'type' in d: choice(d['type'], ASSET_TYPES, 'type')
        if 'ip_address' in d: valid_ip(d['ip_address'])
        if 'criticality' in d: choice(d['criticality'], LEVELS, 'criticality')
        if 'status' in d: choice(d['status'], ('Active', 'Inactive', 'Under Maintenance'), 'status')
        if 'owner_id' in d: ref('users', d['owner_id'])
        return update('assets', id, d, ('name', 'type', 'ip_address', 'operating_system', 'owner_id', 'department', 'location', 'criticality', 'status'))

    @route(H + '/assets/<int:id>', methods=['DELETE'])
    @auth(ADMIN)
    def delete_asset(id):
        return delete('assets', id)
