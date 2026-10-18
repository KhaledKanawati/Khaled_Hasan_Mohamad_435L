# Postman screenshot checklist

The assignment requires screenshots from the running system and the students' own Postman session. Automated test output and saved Postman examples do not replace these screenshots. The current folder has representative service screenshots; capture each case below and embed the images in the matching report section.

## Prepare Postman

1. From the project folder, run `python manage.py seed-demo` and `python serve.py` in separate terminals. Keep the backend running.
2. Import `postman/Security_Incident_Backend.postman_collection.json` (78 workflow requests), `postman/Detailed_Evidence.postman_collection.json` (158 additional cases), and `postman/Local.postman_environment.json`.
3. Select **Security Incident Backend Local**. Run the main workflow from `0 Login` in order. Use the detailed collection for individual validation, permission, search, and lifecycle cases.
4. For each case, capture the Postman request and response so the method, full route, query or body, HTTP status, and response body are readable. For changes, capture the before and after states. Hide bearer tokens and passwords.
5. Add each image to the report under its service. Use the caption format `Student full name – API call – what it does`, for example `Khaled Kanawati – POST /Khaled_Kanawati/users/register – creates an Employee account`.

## Required API captures

### Users and identity — Khaled Kanawati

- Register success, duplicate username, invalid email or weak password, and a SQLite row showing the hashed password.
- Login success and failure.
- Update request, response, and database row before and after.
- Delete as Admin and the same delete denied with 403.
- List users, retrieve an existing username, and retrieve a missing username.
- View roles and permissions as Admin and Auditor; show the Analyst denied; revoke a user's elevated role and show the resulting Employee role.

### Assets — Hasan Zuelghina

- Create multiple assets and show their database rows.
- Reject invalid IP and criticality values.
- Capture before and after an update.
- Delete success and a denied delete with 403.
- List, retrieve an existing asset, and request an invalid ID.
- Search separately by name, type, IP address, department, and criticality.

### Incidents — Mohamad Zuelghina

- Create incidents with different severities and show the database rows. Include an Employee report without an asset.
- List incidents, retrieve one, and request an invalid ID.
- Assign to an Analyst, show the updated incident, and show an unauthorized assignment denied.
- Capture every transition from Open through Under Investigation, Mitigated, Resolved, and Closed. Show an invalid jump rejected.
- Add a note and retrieve the incident with its notes.

### Threat intelligence — Khaled Kanawati

- Add multiple indicator types and show their database rows.
- Reject a duplicate indicator and invalid IP, domain, and file hash values.
- List, retrieve one, request a missing ID, and show each supported search filter.
- Capture before and after an update.
- Delete success and a denied delete with 403.

### Audit logs — Hasan Zuelghina

- Create log records and show their rows.
- List, retrieve one, and request an invalid ID.
- Search separately by user, date, action, severity, and service.
- Retrieve a user's logs when records exist and when none exist.
- Delete as Admin and show a denied delete with 403.

### Security reports — Mohamad Zuelghina

- Capture the summary and all five detailed reports: incidents, assets, threats, vulnerabilities, and activity.
- Compare each total with the matching database count.
- Show an Analyst denied with 403.

### Vulnerabilities — Khaled Kanawati

- Create multiple records and show their database rows.
- List, retrieve one, request an invalid ID, and show each supported search filter.
- Capture before and after an update.
- Show each valid status transition and an invalid transition rejected.
- Delete success and a denied delete with 403.

### Notifications — Hasan Zuelghina

- Create multiple notifications and show their database rows.
- Retrieve a user's notifications when records exist and when none exist; retrieve one and request an invalid ID.
- Capture before and after marking a notification as read.
- Show each supported search filter.
- Delete success and a denied delete with 403.

### Playbooks and actions — Mohamad Zuelghina

- Create multiple playbooks and show their database rows.
- List, retrieve one, and request an invalid ID.
- Add multiple actions and show their step order.
- Capture each valid action status transition and an invalid transition rejected; show the action history rows.
- Delete success and a denied delete with 403.

## Cross-service and database captures

- Show the same protected API call first denied and then allowed with the correct role.
- Show invalid email, a missing field, invalid severity, and malformed asset/IP input with the error response.
- Show all eleven database tables, their keys/relationships, and stored records for each table.
- Capture the current 78-request main collection run after it passes. The existing 75-request run screenshot is from an older collection and must not be used as current evidence.
- Capture the public GitHub repository, branch list, and real commit history. Contribution claims in the report must match work each student actually reviewed and can explain.

## Report integration

Place each screenshot next to the related API explanation. Keep the student name, request title, and purpose in its caption. The architecture and ER diagrams must be embedded as images, with their data flow and entity relationships explained in the text. Update the report's table of contents and page numbers after the screenshots are inserted, then export and inspect the final PDF.
