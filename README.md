# SOC Authentication Monitoring & Detection Lab | Splunk Enterprise

**Training lab — synthetic Windows authentication events; not a real security incident.**

## Overview
I used Splunk Enterprise 10.6.1 to ingest a synthetic CSV dataset representing Windows authentication events, investigate repeated login failures and account lockouts, write SPL detection searches, save reports, and build a three-panel Classic dashboard.

## Environment
- **Platform:** Splunk Enterprise 10.6.1, local lab on macOS
- **Data:** `data/soc_authentication_practice_logs.csv` (14 synthetic events)
- **Splunk sourcetype:** `csv`
- **Splunk host field:** `SOC-LAB-WIN01` (simulated host label)
- **Time scope:** October 21, 2026, 18:00–18:15 (timestamps in the supplied synthetic dataset; no timezone specified)
- **Event codes represented:** 4625 (failed logon), 4624 (successful logon), 4740 (account lockout)

## Findings
| Account | Source IP (documentation range) | Observed pattern |
| --- | --- | --- |
| `alex` | `192.0.2.45` | Eight failed logins (18:00–18:07), then one success (18:08) |
| `sam` | `198.51.100.23` | Three failed logins (18:12–18:14), then one lockout (18:15) |
| `jordan` | `203.0.113.12` | One successful login; no failures in this dataset |

**Event totals:** 11 failed logins, 2 successful logins, 1 lockout (14 total).

The `alex` sequence matched the lab's failed-logins-followed-by-success detection: **8 preceding failures over 8 minutes**. The `sam` sequence was investigated as an account lockout. These patterns warrant triage in a real environment but **do not prove compromise or malicious intent**.

## Investigation workflow
1. Uploaded the CSV into Splunk and confirmed field extraction.
2. Summarized events by `EventCode` and `Outcome`.
3. Grouped failed logins by account and source IP.
4. Compared failures and successes and reviewed chronological timelines.
5. Tested a time-ordered correlation search and saved it as **SOC Lab - Failed Logins Followed by Success**.
6. Investigated lockouts and saved **SOC Lab - Account Lockout Investigation**.
7. Built **SOC Authentication Monitoring Lab**, a Classic dashboard with three panels:
   - Account Lockout Investigation
   - Suspicious Login – Failures Followed by Success
   - Failed Login Attempts by Account

## Detection queries
See [`queries/`](queries/) for the actual SPL searches used in the lab, including the 10-minute sequence-based correlation and lockout summary. The correlation search is a **training proof of concept**, not a production-ready scheduled alert. Its first-failure window and stream ordering have limitations for continuous monitoring, rolling windows, and late-arriving events.

## Evidence
- [SOC investigation report (Word)](reports/SOC_Investigation_Report.docx)
- [Synthetic practice dataset](data/soc_authentication_practice_logs.csv)
- Screenshots of the completed dashboard and search results can be added to [`screenshots/`](screenshots/) after checking them for private information.

## Analyst assessment and limitations
A real SOC investigation would validate account activity with users, inspect original Windows event details, review identity-provider and endpoint telemetry, and assess source-device context and MFA before deciding whether to escalate. In actual Windows events, Event ID 4740 does not necessarily expose the originating IP in the same way as this simplified CSV; correlation with other records may be required.

All data here is synthetic. The IP addresses belong to documentation-only ranges. The lab demonstrates log analysis, SPL, event correlation, report creation, and dashboard visualization—not a confirmed attack or live endpoint monitoring.
