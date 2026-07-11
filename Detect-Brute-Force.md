# Threat Hunting Project: Detecting Brute Force Attacks

## Objective
To identify potential brute force or password spraying attacks by detecting anomalous spikes in failed authentication attempts `(Event ID 4625)` originating from a single IP address.

## The KQL Query
`kusto
// Identify accounts experiencing a high frequency of failed login attempts
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| summarize FailedCount = count() by Account, IpAddress, Computer
| where FailedCount > 10
| sort by FailedCount desc`

## Why This Matters (SOC Context)
High volumes of `Event ID 4625` _(MITRE ATT&CK T1110 - Brute Force)_ indicate that an attacker is attempting to guess user credentials. This is often a precursor to **unauthorized access** and **privilege escalation.**

## Query Breakdown
* `SecurityEvent`: Defines the source table containing Windows security logs.

* `where TimeGenerated > ago(1d)`: Limits the scope to the last 24 hours to ensure the query remains performant and focused on recent activity.

* `where EventID == 4625`: Filters specifically for failed login attempts.

* `summarize FailedCount = count() by Account, IpAddress, Computer`: The core of the query. It groups the results so that I can see exactly how many failed attempts `(count())` were linked to a specific combination of `user`, `IP address`, and `machine`.

* `where FailedCount > 10`: A noise-reduction filter. It discards legitimate users who might have mistyped their password once or twice, focusing only on high-volume attempts.

* `sort by FailedCount desc`: Presents the worst offenders at the top of the list for immediate attention.


## Analyst Investigation Steps
If this query flags multiple failed logins for a single account:

* **Validate the Source:** Check if the `IpAddress` is an internal office IP (which might indicate a user just forgot their password) or an external/malicious IP (which indicates an attack).

* **Review Account Activity:** Use the `Account` name to see if there were any successful logins immediately following the failed attempts.

* **Take Action:** If the activity is suspicious, lock the compromised account, trigger a password reset, and block the offending `IpAddress` at the firewall level.

🧠 Hindsights

* The `summarize` Operator: I learned that `summarize` is one of the most powerful tools in KQL. It allows me to group massive amounts of data by specific fields (`Account`, `IP`) to turn noise into a clean, actionable list of "top offenders."

* `Threshold` Tuning: I set the `threshold` to `> 10` for this lab, but in a real enterprise, I’d need to tune this based on historical "normal" behavior to avoid alerting on every user who has a bad memory!

* Performance: I placed the `TimeGenerated` and `EventID` filters at the top because KQL processes data from left to right; filtering before summarizing significantly reduces the amount of data the engine has to process.
  
