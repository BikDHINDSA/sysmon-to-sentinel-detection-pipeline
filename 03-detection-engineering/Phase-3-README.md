# Phase 3: Detection Engineering

This phase builds Microsoft Sentinel analytics rules to detect each stage of the Phase 2 attack chain, using the telemetry pipeline established in Phase 1. Each rule was developed and validated against the raw events confirmed in Phase 2, then tested live by re-running the corresponding attack stage after the rule was active.

## Approach

Detection queries were written and tested manually against existing log data first, then saved as scheduled Analytics Rules, then validated a second time by re-triggering the attack stage and confirming an incident was generated automatically — not just that the query could find historical matches. This distinction matters: a query that finds existing rows proves the KQL logic is correct, while an automatically generated incident proves the entire pipeline (Sysmon/Security auditing → AMA → DCR → Sentinel → Analytics Rule → Incident) works unattended, the way it would in production.

Two independent telemetry sources — native Windows Security auditing and Sysmon — were used where possible, so detection coverage for a given technique isn't dependent on a single log source.

## Rules Overview

<img src="./screenshots/all-rules-overview.png" alt="All Active Analytics Rules" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

| Rule Name | MITRE ATT&CK | Severity | Table |
| :--- | :--- | :--- | :--- |
| Suspicious Powershell Download Cradle | T1059.001, T1071 (Execution, Command and Control) | High | SecurityEvent |
| Registry Run Key Persistence | T1547.001 (Persistence) | High | Event (Sysmon) |
| Scheduled Task Creation | T1053.005 (Persistence) | Medium | SecurityEvent |
| Discovery Command Sequence | T1049, T1057, T1082, T1087 (Discovery) | Medium | SecurityEvent |

All rules run on a 5-minute schedule, checking the last 5 minutes of data, and trigger an alert if the query returns more than 0 results.

---

## Rule 1: Suspicious PowerShell Download Cradle

**Detects:** Stage 1 — fileless execution via a PowerShell download-and-execute pattern.

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has "DownloadString" and CommandLine has "IEX"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
```

<img src="./screenshots/rule-wizard-set-logic-download-cradle.png" alt="Rule 1 - Set Rule Logic" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

<img src="./screenshots/rule-powershell-download-cradle.png" alt="Rule 1 - Review and Create" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

**Query validation (prior to rule creation):**

<img src="./screenshots/query-test-download-cradle-securityevent.png" alt="Rule 1 - Manual Query Validation, SecurityEvent" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

A parallel query against the Sysmon-sourced `Event` table was also validated, confirming the same activity independently of native Windows auditing:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "DownloadString" or RenderedDescription has "IEX"
| extend CommandLine = extract(@"CommandLine:\s*(.*?)(\r\n|\n|$)", 1, RenderedDescription)
| extend ParentCommandLine = extract(@"ParentCommandLine:\s*(.*?)(\r\n|\n|$)", 1, RenderedDescription)
| project TimeGenerated, Computer, CommandLine, ParentCommandLine
```

<img src="./screenshots/query-test-download-cradle-sysmon.png" alt="Rule 1 - Manual Query Validation, Sysmon" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

---

## Rule 2: Registry Run Key Persistence

**Detects:** Stage 2 — a value written to a Run key, a common autostart persistence mechanism.

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend TargetObject = extract(@'Name="TargetObject">([^<]+)<', 1, EventData)
| extend Details = extract(@'Name="Details">([^<]+)<', 1, EventData)
| extend Image = extract(@'Name="Image">([^<]+)<', 1, EventData)
| where TargetObject has @"CurrentVersion\Run"
| project TimeGenerated, Computer, Image, TargetObject, Details
```

**Note:** this registry subtree is also written to by legitimate Windows components — application inventory telemetry from `svchost.exe` was observed in this environment during testing. The `where TargetObject has @"CurrentVersion\Run"` filter is deliberately scoped to the Run key path itself, rather than alerting on every Event ID 13 write, to exclude this native background noise.

<img src="./screenshots/rule-registry-run-key-persistence.png" alt="Rule 2 - Review and Create" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

**Query validation:**

<img src="./screenshots/query-test-registry-runkey.png" alt="Rule 2 - Manual Query Validation" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

---

## Rule 3: Scheduled Task Creation

**Detects:** Stage 3 — an independent persistence mechanism via a scheduled task.

```kql
SecurityEvent
| where EventID == 4698
| project TimeGenerated, Computer, SubjectUserName, TaskName, TaskContentNew
```

A parallel Sysmon-based query, catching the underlying `schtasks.exe` process invocation directly, was also validated:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend Image = extract(@'Name="Image">([^<]+)<', 1, EventData)
| extend CommandLine = extract(@'Name="CommandLine">([^<]+)<', 1, EventData)
| extend ParentImage = extract(@'Name="ParentImage">([^<]+)<', 1, EventData)
| where Image has "schtasks.exe" or CommandLine has "schtasks"
| project TimeGenerated, Computer, Image, CommandLine, ParentImage
```

**Note:** Event ID 4698 requires the `Other Object Access Events` audit subcategory, which is not enabled by default (see Phase 1). It also requires `SCENoApplyLegacyAuditPolicy` to be set — without it, Windows can silently ignore the subcategory setting entirely, producing no 4698 events despite `auditpol` reporting success.

<img src="./screenshots/rule-scheduled-task-creation.png" alt="Rule 3 - Review and Create" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

**Query validation:**

<img src="./screenshots/query-test-scheduled-task-sysmon.png" alt="Rule 3 - Manual Query Validation, Sysmon" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

---

## Rule 4: Discovery Command Sequence

**Detects:** Stage 4 — post-compromise reconnaissance, alerting on a *sequence* of distinct discovery commands from the same account in a short window, rather than any single command in isolation (each individual command is common in legitimate administrative activity).

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("whoami", "net user", "net localgroup", "systeminfo", "tasklist", "netstat")
| summarize count(), make_set(CommandLine) by Computer, Account, bin(TimeGenerated, 5m)
| where count_ >= 3
```

<img src="./screenshots/rule-discovery-command-sequence.png" alt="Rule 4 - Review and Create" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

**Query validation:**

<img src="./screenshots/query-test-discovery-commands.png" alt="Rule 4 - Manual Query Validation" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

---

## Telemetry Pipeline Verification

Before rule development began, both log sources were independently confirmed as flowing correctly:

<img src="./screenshots/verify-sysmon-log-flow.png" alt="Sysmon Log Flow Verification" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

<img src="./screenshots/verify-securityevent-log-flow.png" alt="Security Event Log Flow Verification" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

## Phase 3 Completion Criteria

**Phase 3 is considered complete when:**

1. All four analytics rules are created, enabled, and correctly mapped to their MITRE ATT&CK techniques.
2. Each rule's KQL query has been validated manually against Phase 2's raw telemetry.
3. Each rule has been confirmed to generate a live incident automatically after re-running the corresponding attack stage.
4. Detection coverage exists across at least two independent telemetry sources where the technique allows for it.

---

***Phase 3 establishes automated detection over the Phase 2 attack chain. Incident investigation and reporting are handled in Phase 4.***