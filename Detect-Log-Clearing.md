# Threat Hunting Project: Detecting Windows Event Log Clearing

## Objective
To identify anti-forensic behavior by detecting when an attacker attempts to clear the Windows Security Event log to hide malicious activity.

## The KQL Query
```kusto
// Find instances where the Windows Security Event Log was intentionally cleared
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity

Why This Matters (SOC Context)
Attackers frequently use the command wevtutil.exe cl or PowerShell commands to wipe event logs immediately after compromising a system (MITRE ATT&CK T1070.001 - Indicator Removal on Host: Clear Windows Event Logs). Detecting Event ID 1102 allows a SOC analyst to catch this defense evasion tactic in real-time.

Analyst Investigation Steps
If this query fires an alert in production, a SOC Analyst should:

Identify the user account in the Account column and determine if it belongs to a legitimate domain administrator performing scheduled maintenance.

Correlate the timeline to check what actions that specific Computer and Account performed immediately before the log was cleared.

Treat unexplained log-clearing by non-administrative or unusual service accounts as a critical true-positive incident and isolate the host machine from the network.

🧠 Sandbox Lessons & KQL Gotchas
The TimeGenerated Trap: I learned that placing your time filter (| where TimeGenerated > ago(7d)) at the very top of your query drastically reduces data processing costs and speeds up execution—critical for a busy SOC environment.

Efficiency: In a real SIEM, running queries without strict time boundaries is a great way to timeout your session and slow down the entire platform.
