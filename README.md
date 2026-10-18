# Security Incident Detection and Response Backend

Sprint I includes nine Flask REST services, a gateway, SQLite storage, role checks, Postman requests, and tests. No frontend is required.

## Submission layout

- `01_Source_Code.zip`: self-contained source, tests, tools, schema, API documentation, and both Postman collections. Extract this ZIP alone to run the tests.
- `02_Database.zip`: SQLite snapshot and schema script from the verification session.
- `03_Postman.zip`: convenient copies of the collections and environment for import.
- `04_Evidence.zip`: genuine captured screenshots, recorded HTTP request/response JSON, and database records. HTTP transcripts are labeled as transcripts, not Postman screenshots.
- `Final_Report.docx`: shared report with diagrams, service explanations, API details, and embedded evidence.
- `Final_Report.txt`: text companion; images remain in the DOCX.
- `GitHub_Repository.txt`: repository URL and branch information.

The source ZIP does not depend on any sibling ZIP. Its `postman/`, `data/schema.sql`, and `docs/` are included. Runtime database and screenshot evidence are supplied separately.

## Run locally

Use Python 3.11 or newer in the extracted source folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = 'choose-a-long-random-local-secret'
python manage.py seed-demo
python serve.py
```

The gateway runs at `http://127.0.0.1:5000`; the nine services use ports 5101-5109. `GET /health` lists the services. Stop with Ctrl+C. `python app.py` runs all routes together for debugging. Set `GATEWAY_PORT`, `SERVICE_PORT` (the first of nine consecutive service ports), or `DATABASE` to use another local setup.

`seed-demo` creates `admin`, `analyst`, `employee`, and `auditor`, each using `DemoPass123!`. These are demonstration credentials. The server creates `data/security.db` on startup. The `.gitignore` excludes runtime `.db` files from Git; the submission deliberately includes a separate database snapshot in `02_Database.zip`.

## Feature ownership

| Feature | Student | Route prefix |
| --- | --- | --- |
| Users | Khaled Kanawati | `/Khaled_Kanawati/users` |
| Assets | Hasan Zuelghina | `/Hasan_Zuelghina/assets` |
| Incidents | Mohamad Zuelghina | `/Mohamad_Zuelghina/incidents` |
| Threats | Khaled Kanawati | `/Khaled_Kanawati/threats` |
| Audit logs | Hasan Zuelghina | `/Hasan_Zuelghina/logs` |
| Reports | Mohamad Zuelghina | `/Mohamad_Zuelghina/reports` |
| Vulnerabilities | Khaled Kanawati | `/Khaled_Kanawati/vulnerabilities` |
| Notifications | Hasan Zuelghina | `/Hasan_Zuelghina/notifications` |
| Playbooks | Mohamad Zuelghina | `/Mohamad_Zuelghina/playbooks` |

## Postman and tests

Import `postman/Local.postman_environment.json` and a collection, select **Security Incident Backend Local**, then run folders in order. The standard collection has 78 requests; `Detailed_Evidence.postman_collection.json` adds 158 detailed cases. Tokens and IDs are saved automatically. The detailed collection creates a fresh run tag for unique usernames and indicators.

```powershell
python -m pytest -q
python tools/build_postman.py
python tools/build_evidence.py
```

The suite has 20 tests, including both complete collections. Tests use temporary databases. Regeneration replaces any recorded response examples, while preserving runnable request definitions. For actual HTTP recording with the server running:

```powershell
python tools/run_evidence.py
```

This writes actual HTTP results and database snapshots to `evidence/`. These records are not simulated screenshots. Every request has a description and an expected HTTP status. See [API reference](docs/API.md) for methods, paths, fields, and possible errors.

## Authentication and access

Passwords use Werkzeug salted hashes. Login returns a signed bearer token valid for 24 hours. Every protected request reads the current user role and status, so revoking access affects existing tokens immediately. Self-registration always creates Employees; only Admin can assign roles or change account status. Auditors read without modifying records. Employees see their own incidents and notifications; Analysts see assigned incidents.

`GET /Khaled_Kanawati/users/roles` lists role permissions for Admin and Auditor. `GET /Khaled_Kanawati/users/{id}/roles` shows a user's assigned role and routes. `DELETE /Khaled_Kanawati/users/{id}/role` lets Admin revoke elevated access, retaining the base Employee role. An Admin cannot revoke their own role through that endpoint. Permissions list route access; ownership and analyst assignment add record-level checks.

Employees can report an incident without an `asset_id`; it remains SQL NULL until an asset is known. If supplied, the ID must reference an existing asset. User-provided `reporter_id` is ignored for Employees.

## Database design

Nine service processes share one SQLite file. This classroom design keeps setup small; services do not have separate databases. Reports still fetch data through the other service APIs, and incident/threat/vulnerability workflows call the notification API. Foreign keys, unique constraints, parameterized SQL, and input validation preserve relationships and reject malformed input. The schema is in `db.py` and `data/schema.sql`.

## Repository and coaching

Repository: https://github.com/KhaledKanawati/Khaled_Hasan_Mohamad_435L

The repository retains its original `_435L` name. The submitted folder uses `430L`, the suffix explicitly written in the assignment brief. They refer to the same project.

The team reported attending CREATES on Friday 16 October 2026, mainly receiving README formatting feedback. The README was reorganized around the submission layout, setup, testing, ownership, and file paths.

## AI assistance and contributions

AI assistance was used to generate and refine backend code, tests, Postman requests, documentation, report prose, and packaging, and to diagnose failures. It also prepared commits using the names and emails supplied by the team. The feature map records assigned ownership; commit author labels alone do not establish independently authored student work. Each member must review and explain the assigned features and make their own substantive contributions. The report uses the same disclosure. Instructor acceptance of that assistance must be established by the team.
