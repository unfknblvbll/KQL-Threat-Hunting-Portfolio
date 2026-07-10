![KQL](https://img.shields.io/badge/Language-KQL-purple?style=for-the-badge)

# Threat Hunting Project: Detecting Windows Event Log Clearing

## Objective
To identify anti-forensic behavior by detecting when an attacker attempts to clear the Windows Security Event log to hide malicious activity.

## The KQL Query

`kusto
// Find instances where the Windows Security Event Log was intentionally cleared
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity`


### Why This Matters (SOC Context)
Attackers frequently use the command ```wevtutil.exe cl``` or PowerShell commands to wipe event logs immediately after compromising a system _(MITRE ATT&CK T1070.001 - Indicator Removal on Host: Clear Windows Event Logs)._ Detecting Event ID 1102 allows a SOC analyst to catch this defense evasion tactic in real-time.

## Analyst Investigation Steps
If this query fires an alert in production, a SOC Analyst should:

* Identify the user account in the `Account` column and determine if it belongs to a legitimate domain administrator performing scheduled maintenance.

* Review logs prior to the clearing event to identify the malicious activity that triggered the need for log erasure.

* Treat unexplained log-clearing by _non-administrative_ or _unusual service accounts_ as a critical `true-positive` incident and isolate the host machine from the network.


## 🧠 Hindsights

* **The `TimeGenerated` Trap:** I learned early on that placing your time filter (like `| where TimeGenerated > ago(7d)`) at the *very top* of your query instead of the bottom drastically reduces data processing costs and speeds up query execution. Efficiency matters in a busy SOC!
* **Case Sensitivity:** Remembering that string operators like `==` are case-sensitive in KQL, while `has` or `contains` are not. (Saved myself a few hours of troubleshooting logs by figuring that out!)
* **Efficiency:** In a real SIEM, running queries without strict time boundaries is a great way to timeout your session and slow down the entire platform.
