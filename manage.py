import sys
from werkzeug.security import generate_password_hash
from app import create_app
from db import one, run


def create_user(name, username, role, password):
    if one('SELECT id FROM users WHERE username=?', (username,)):
        return
    run('INSERT INTO users(full_name,username,email,password_hash,department,role) VALUES(?,?,?,?,?,?)',
        (name, username, f'{username}@example.test', generate_password_hash(password), 'Security', role))


def main():
    if len(sys.argv) != 2 or sys.argv[1] != 'seed-demo':
        raise SystemExit('Usage: python manage.py seed-demo')
    app = create_app()
    with app.app_context():
        # Local demonstration accounts; change these before using real data.
        for name, username, role in (
            ('Demo Administrator', 'admin', 'Admin'),
            ('Demo Analyst', 'analyst', 'Analyst'),
            ('Demo Employee', 'employee', 'Employee'),
            ('Demo Auditor', 'auditor', 'Auditor'),
        ):
            create_user(name, username, role, 'DemoPass123!')
        print('Demo users are ready. Password: DemoPass123!')


if __name__ == '__main__':
    main()
