# Screenshot and report evidence guide

Capture every image from the running local API, your own Postman session, SQLite database, or actual GitHub repository. The assignment does not accept generated or simulated screenshots. Use the provided folders only after taking real captures.

## Start a repeatable session

1. In the project folder, run `python -m pytest -q` and capture the passing terminal result if you want test evidence.
2. Run `python manage.py seed-demo`, then `python serve.py` in a terminal. Keep the server open.
3. Import both JSON files from `postman/`, select **Security Incident Backend Local**, and run the collection folders in order. The four `0 Login` requests save role tokens. Creation requests save IDs for later requests.
4. The final **Delete demos** folder creates temporary records, then deletes them. Run it after capturing the main records. The collection uses fresh names for unique values when repeated.
5. For each screenshot, show the Postman method, full named route, request body or query parameters, response status, and response body in one view. Show the student name in the caption as well. Suggested caption: `Khaled Kanawati — POST /Khaled_Kanawati/users/register — creates an Employee account`.

## Capture checklist

| Folder | Minimum live captures |
| --- | --- |
| `01-users` | Registration success and duplicate 409; good and bad login; profile update; all users; existing and missing username; authorized and denied delete; SQLite row with password hash. |
| `02-assets` | Two asset creations, before and after update, allowed and denied delete, list, one existing and missing ID, several searches, SQLite asset rows. |
| `03-incidents` | Incidents of different severities; list and detail; missing ID; authorized and denied assignment; all four status transitions; invalid transition; note creation and detail with note; SQLite rows. |
| `04-threats` | Multiple indicator types, duplicate 409, list and detail, missing ID, searches, update before and after, allowed and denied delete, SQLite rows. |
| `05-logs` | Successful and failed login log entries; denied access log; all, one, missing ID, searches, user logs with results and an empty result, allowed and denied delete, SQLite rows. |
| `06-reports` | Summary, incidents, assets, threats, vulnerabilities, activity; compare each total against actual database rows. |
| `07-vulnerabilities` | Multiple records and severities; list, detail, missing ID, searches, update before and after; complete status path and rejected skip; allowed and denied delete; SQLite rows. |
| `08-notifications` | Create multiple notices, user list and empty list, detail and missing ID, unread then read, searches, allowed and denied delete; SQLite rows. |
| `09-playbooks` | Multiple playbooks, list and detail with ordered actions, missing ID, two actions, status progress and rejected skip, allowed and denied delete; SQLite action history. |
| `10-git` | GitHub branch list, real commit history, pull requests/merges, and each person's actual contributions. |

Use the **Evidence checks** folder for denied access, malformed IP, invalid incident transition, failed login, and missing asset ID. Use **Delete demos** for successful deletions. For access control, pair a failed request with the same endpoint using an authorized role. For state changes, capture before and after Postman responses plus the corresponding database row.

## Database screenshots

Open `data/security.db` in a SQLite viewer after making requests. Show table names, column keys, foreign keys, and sample rows. Useful SQL in a SQLite query window:

```sql
PRAGMA foreign_key_list(incidents);
SELECT id, username, role, status, password_hash FROM users;
SELECT id, name, criticality, status FROM assets;
SELECT id, title, severity, status, analyst_id FROM incidents;
SELECT id, action, severity, service, created_at FROM logs ORDER BY id DESC;
SELECT id, action_id, status, actor_id FROM action_history ORDER BY id;
```

Crop or hide bearer tokens and demo passwords in report images. Leave enough of the request and response visible to show the actual operation.

## Report outline

Use the assignment's report order: title page; table of contents with page numbers and responsible names; introduction; architecture; implementation for all nine features; database design; validation and errors; API documentation; authentication and authorization; GitHub history; references. Put the full responsible student name next to each feature and in each screenshot caption. Include the Mermaid database diagram from `README.md`, and describe the nine local HTTP services, gateway, and shared SQLite database accurately. The report must state where AI assistance was used and what each person actually reviewed or implemented.
