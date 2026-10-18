# API reference

Base URL: `http://127.0.0.1:5000`. Each route begins with the full name of the student assigned to that feature.

Send `Authorization: Bearer <token>` for protected calls. Login returns the token. JSON bodies use `Content-Type: application/json`.

Responses are JSON objects for one record or a report, and JSON arrays for lists and searches. New records return HTTP 201.
Errors return `{"status":"error","message":"..."}` with HTTP 400 (validation), 401 (authentication), 403 (permission), 404 (missing record), or 409 (duplicate/relationship conflict).
Requests that accept JSON bodies include editable examples in the collection.
Search filters combine with AND. IDs, IP addresses, types, severities, statuses, and criticality use exact matches. Other text filters support partial matches; `created_at` accepts a date or timestamp fragment.

## 1 Users (Khaled Kanawati)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Register User | POST | `/Khaled_Kanawati/users/register` | full_name, username, email, password, department | 201 record |
| Create User | POST | `/Khaled_Kanawati/users` | full_name, username, email, password, department, role | 201 record |
| Login | POST | `/Khaled_Kanawati/users/login` | username, password | 200 JSON |
| Users | GET | `/Khaled_Kanawati/users` | Path ID, if present | 200 JSON |
| User By Name | GET | `/Khaled_Kanawati/users/{{username}}` | Path ID, if present | 200 JSON |
| Update User | PUT | `/Khaled_Kanawati/users/{{userId}}` | full_name, email, department | 200 JSON |
| User Role | PUT | `/Khaled_Kanawati/users/{{userId}}/role` | role | 200 JSON |
| Roles And Permissions | GET | `/Khaled_Kanawati/users/roles` | Path ID, if present | 200 JSON |
| View User Roles | GET | `/Khaled_Kanawati/users/{{userId}}/roles` | Path ID, if present | 200 JSON |
| Remove User Role | DELETE | `/Khaled_Kanawati/users/{{userId}}/role` | Path ID, if present | 200 message |
| User Status | PUT | `/Khaled_Kanawati/users/{{userId}}/status` | status | 200 JSON |
| Delete User | DELETE | `/Khaled_Kanawati/users/{{userId}}` | Path ID, if present | 200 message |

## 2 Assets (Hasan Zuelghina)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Create Asset | POST | `/Hasan_Zuelghina/assets` | name, type, ip_address, department, owner_id, criticality, status, location | 201 record |
| Assets | GET | `/Hasan_Zuelghina/assets` | Path ID, if present | 200 JSON |
| Assets Search | GET | `/Hasan_Zuelghina/assets/search?name=web&type=Server&ip_address=10.0.0.10&department=IT&criticality=High` | name, type, ip_address, department, criticality | 200 JSON |
| Asset | GET | `/Hasan_Zuelghina/assets/{{assetId}}` | Path ID, if present | 200 JSON |
| Asset History | GET | `/Hasan_Zuelghina/assets/{{assetId}}/history` | Path ID, if present | 200 JSON |
| Update Asset | PUT | `/Hasan_Zuelghina/assets/{{assetId}}` | criticality, status | 200 JSON |
| Delete Asset | DELETE | `/Hasan_Zuelghina/assets/{{assetId}}` | Path ID, if present | 200 message |

## 3 Incidents (Mohamad Zuelghina)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Create Incident | POST | `/Mohamad_Zuelghina/incidents` | title, description, category, severity, reporter_id, asset_id | 201 record |
| Incidents | GET | `/Mohamad_Zuelghina/incidents` | Path ID, if present | 200 JSON |
| Incident | GET | `/Mohamad_Zuelghina/incidents/{{incidentId}}` | Path ID, if present | 200 JSON |
| Assign Incident | PUT | `/Mohamad_Zuelghina/incidents/{{incidentId}}/assign` | analyst_id | 200 JSON |
| Incident Status | PUT | `/Mohamad_Zuelghina/incidents/{{incidentId}}/status` | status | 200 JSON |
| Add Note | POST | `/Mohamad_Zuelghina/incidents/{{incidentId}}/notes` | content | 201 record |

## 4 Threats (Khaled Kanawati)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Create Threat | POST | `/Khaled_Kanawati/threats` | type, value, description, severity, source | 201 record |
| Threats | GET | `/Khaled_Kanawati/threats` | Path ID, if present | 200 JSON |
| Threats Search | GET | `/Khaled_Kanawati/threats/search?type=Domain&severity=High&source=SOC` | type, value, severity, source | 200 JSON |
| Threat | GET | `/Khaled_Kanawati/threats/{{threatId}}` | Path ID, if present | 200 JSON |
| Update Threat | PUT | `/Khaled_Kanawati/threats/{{threatId}}` | description, severity, source | 200 JSON |
| Delete Threat | DELETE | `/Khaled_Kanawati/threats/{{threatId}}` | Path ID, if present | 200 message |

## 5 Audit logs (Hasan Zuelghina)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Create Log | POST | `/Hasan_Zuelghina/logs` | user_id, action, description, severity, service | 201 record |
| Logs | GET | `/Hasan_Zuelghina/logs` | Path ID, if present | 200 JSON |
| Logs Search | GET | `/Hasan_Zuelghina/logs/search?user_id={{adminId}}&severity=Information&service=reports` | user_id, created_at, action, severity, service | 200 JSON |
| User Logs | GET | `/Hasan_Zuelghina/logs/user/{{adminId}}` | Path ID, if present | 200 JSON |
| Log | GET | `/Hasan_Zuelghina/logs/{{logId}}` | Path ID, if present | 200 JSON |
| Delete Log | DELETE | `/Hasan_Zuelghina/logs/{{logId}}` | Path ID, if present | 200 message |

## 6 Reports (Mohamad Zuelghina)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Summary | GET | `/Mohamad_Zuelghina/reports/summary` | Path ID, if present | 200 JSON |
| Incident Report | GET | `/Mohamad_Zuelghina/reports/incidents` | Path ID, if present | 200 JSON |
| Asset Report | GET | `/Mohamad_Zuelghina/reports/assets` | Path ID, if present | 200 JSON |
| Threat Report | GET | `/Mohamad_Zuelghina/reports/threats` | Path ID, if present | 200 JSON |
| Vulnerability Report | GET | `/Mohamad_Zuelghina/reports/vulnerabilities` | Path ID, if present | 200 JSON |
| Activity Report | GET | `/Mohamad_Zuelghina/reports/activity` | Path ID, if present | 200 JSON |

## 7 Vulnerabilities (Khaled Kanawati)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Create Vulnerability | POST | `/Khaled_Kanawati/vulnerabilities` | title, description, cve, cvss, severity, asset_id, source | 201 record |
| Vulnerabilities | GET | `/Khaled_Kanawati/vulnerabilities` | Path ID, if present | 200 JSON |
| Vulnerability Search | GET | `/Khaled_Kanawati/vulnerabilities/search?cve=CVE-2025-1234&severity=High&asset_id={{assetId}}&status=Open` | cve, severity, asset_id, status | 200 JSON |
| Vulnerability | GET | `/Khaled_Kanawati/vulnerabilities/{{vulnerabilityId}}` | Path ID, if present | 200 JSON |
| Update Vulnerability | PUT | `/Khaled_Kanawati/vulnerabilities/{{vulnerabilityId}}` | status, description | 200 JSON |
| Delete Vulnerability | DELETE | `/Khaled_Kanawati/vulnerabilities/{{vulnerabilityId}}` | Path ID, if present | 200 message |

## 8 Notifications (Hasan Zuelghina)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Create Notification | POST | `/Hasan_Zuelghina/notifications` | user_id, title, message, type, severity | 201 record |
| User Notifications | GET | `/Hasan_Zuelghina/notifications/user/{{employeeId}}` | Path ID, if present | 200 JSON |
| Notifications Search | GET | `/Hasan_Zuelghina/notifications/search?user_id={{employeeId}}&type=Security%20Alert&severity=Medium&status=Unread` | user_id, type, severity, status | 200 JSON |
| Notification | GET | `/Hasan_Zuelghina/notifications/{{notificationId}}` | Path ID, if present | 200 JSON |
| Read Notification | PUT | `/Hasan_Zuelghina/notifications/{{notificationId}}/read` | Path ID, if present | 200 JSON |
| Delete Notification | DELETE | `/Hasan_Zuelghina/notifications/{{notificationId}}` | Path ID, if present | 200 message |

## 9 Playbooks (Mohamad Zuelghina)

| API | Method | Endpoint | Request fields | Success |
| --- | --- | --- | --- | --- |
| Create Playbook | POST | `/Mohamad_Zuelghina/playbooks` | name, description, category, severity | 201 record |
| Playbooks | GET | `/Mohamad_Zuelghina/playbooks` | Path ID, if present | 200 JSON |
| Playbook | GET | `/Mohamad_Zuelghina/playbooks/{{playbookId}}` | Path ID, if present | 200 JSON |
| Create Action | POST | `/Mohamad_Zuelghina/playbooks/{{playbookId}}/actions` | description, step_no | 201 record |
| Action Status | PUT | `/Mohamad_Zuelghina/actions/{{actionId}}/status` | status, assigned_user_id | 200 JSON |
| Delete Playbook | DELETE | `/Mohamad_Zuelghina/playbooks/{{playbookId}}` | Path ID, if present | 200 message |

## Optional incident asset and role revocation

An incident can be reported without `asset_id`; the stored value is null. A supplied asset ID must exist. The reporter is always taken from the authenticated user.

`DELETE /Khaled_Kanawati/users/{id}/role` is Admin-only and returns the user to the mandatory Employee role. An Admin cannot revoke their own role. Role catalogs and per-user permissions are available to Admin and Auditor through the two GET role endpoints.
