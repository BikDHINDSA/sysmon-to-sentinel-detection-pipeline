# SOC Capstone — Addendum to Original PLAN (v2 Rebuild)

This captures everything that changed from the original guide during the actual build, due to real-world Azure behavior, hardware constraints, and lessons learned. Keep this alongside the original guide — treat this as the "what actually happened and why" layer.

---

## Change 1: Bastion instead of direct RDP

**Why:** 2017 MacBook Pro can't run macOS 14+, which the Windows App (RDP client) requires. Rather than fight FreeRDP install issues, switched to Azure Bastion.

**What this changes in Phase 1:**
- VM created **without a public IP** (`--public-ip-address ""` in CLI)
- Added `AzureBastionSubnet` (`10.0.1.0/26`) alongside the VM's subnet (`10.0.0.0/24`)
- VM's NSG restricted to allow RDP (3389) **only from `10.0.1.0/26`** — no public internet access to RDP at all
- Connect via VM's page → **Connect → Bastion**, not a downloaded RDP file

**Why this is a legitimate design choice, not just a workaround (use this framing in your README):**
Eliminates a public-facing RDP attack surface entirely — a real hardening decision, not just a Mac compatibility fix. Worth a line in your Phase 1 write-up.

**Screenshots to add to `01-environment-setup/`:**
```
bastion-subnet-created.png
bastion-deployed.png
vm-nsg-restricted-to-bastion.png
bastion-connection-success.png
```

---

## Change 2: Log Analytics workspace rebuilt fresh (v2)

**Why:** First workspace (`law-soc-lab`) hit a persistent, unresolved "Unauthorized" error on analytics rule creation, likely tied to soft-delete/recreate history. Full resource group rebuild was faster than continued debugging.

**What changed:**
- Workspace renamed `law-soc-lab-v2` (avoid reusing soft-deleted names going forward)
- Resource providers explicitly registered **before** any resource creation: `Microsoft.Compute`, `Microsoft.Network`, `Microsoft.OperationalInsights`, `Microsoft.SecurityInsights`, `Microsoft.Insights`
- RBAC roles assigned proactively on the resource group, before building anything: **Microsoft Sentinel Contributor** + **Log Analytics Contributor** (in addition to subscription-level Owner)
- A **throwaway test analytics rule** (`SecurityEvent | take 1`) is created immediately after enabling Sentinel, before building the VM or anything else — confirms the whole permission chain works in ~2 minutes rather than discovering a break hours later

**VM size/region note:** `Standard_B1s`/B-series repeatedly hit capacity and quota restrictions across multiple regions (Canada Central, East US, Canada East, West US 2). Settled on **`Standard_D2s_v7` in Central US**, confirmed via `az vm list-skus` to have zero restrictions.

---

## Change 3: Sysmon logs require a split Data Collection Rule

**The problem:** Bundling both `Security!*` and `Microsoft-Windows-Sysmon/Operational!*` XPath queries under one stream (`Microsoft-SecurityEvent`) caused silent failure — Sysmon's event schema isn't compatible with that stream, and it broke ingestion for the whole data source.

**The fix — two separate dataSources, two separate streams, two matching dataFlows:**

```json
"dataSources": {
  "windowsEventLogs": [
    {
      "name": "securityEventDataSource",
      "streams": ["Microsoft-SecurityEvent"],
      "xPathQueries": ["Security!*"]
    },
    {
      "name": "sysmonEventDataSource",
      "streams": ["Microsoft-Event"],
      "xPathQueries": ["Microsoft-Windows-Sysmon/Operational!*"]
    }
  ]
},
"dataFlows": [
  { "destinations": ["DataCollectionEvent"], "streams": ["Microsoft-SecurityEvent"] },
  { "destinations": ["DataCollectionEvent"], "streams": ["Microsoft-Event"] }
]
```

**Where each source lands:**
| Source | Table | Notes |
|---|---|---|
| Security log (4688, etc.) | `SecurityEvent` | Clean, pre-parsed columns (`CommandLine`, `Account`, etc.) |
| Sysmon | `Event` | Raw text in `RenderedDescription`, needs `extract()` to pull fields |

**Worth a specific line in your documentation:** this is a genuinely useful, precise technical detail — "Sysmon events collected via custom XPath route to the generic `Event` table rather than `SecurityEvent`, since AMA routing is stream-based, not connector-based" — shows real hands-on troubleshooting, not tutorial-following.

---

## Change 4: Windows Security auditing (4688) isn't on by default

**The problem:** Ran stage 1 attack simulation, checked `SecurityEvent` for EventID 4688 — nothing. Not a pipeline bug: **Windows doesn't log process creation by default.**

**The fix — run on the VM (PowerShell, as Administrator), before generating any events you want captured this way:**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force
```
**Not retroactive** — only events after this point get logged with 4688. Re-trigger any attack stage you want to see captured this way, after running these two commands.

**Decision point:** Sysmon Event ID 1 already captures process creation richly (command line, parent process, hashes) with zero extra config. Enabling 4688 is optional — valuable to show you understand both native auditing and Sysmon, but not required for the project to function.

---

## Change 5: Detection query patterns differ by table

**Sysmon (`Event` table) — needs regex extraction, since fields are embedded in one text blob:**
```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "DownloadString" or RenderedDescription has "IEX"
| extend CommandLine = extract(@"CommandLine:\s*(.*?)(\r\n|\n|$)", 1, RenderedDescription)
| extend ParentCommandLine = extract(@"ParentCommandLine:\s*(.*?)(\r\n|\n|$)", 1, RenderedDescription)
| project TimeGenerated, Computer, CommandLine, ParentCommandLine
```
*(Confirm actual line-break characters in your raw `RenderedDescription` first — single vs. double backslash escaping depends on how the text is actually stored; test against one real row before relying on this.)*

**Security (`SecurityEvent` table) — clean columns already, no regex needed:**
```kusto
SecurityEvent
| where EventID == 4688
| where CommandLine has "DownloadString" or CommandLine has "IEX"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName, NewProcessName
```

---

## Change 6: Revised order of operations for attack simulation + detection (Phase 2 → Phase 3)

**Original assumption:** run all attacks → build all detections → done.

**Corrected sequence — this is the actual credible version:**

1. **Per attack stage**, before running anything: write down the technique, MITRE ID, and *expected* log signature in `02-attack-simulation/`
2. Run **one** stage's command
3. Wait ~3-5 min, query logs to confirm the *raw event* landed (manual KQL query, not yet a saved rule)
4. Screenshot: command execution + raw log entry
5. Repeat steps 2-4 for each remaining stage
6. **Only after all raw telemetry is confirmed**, build your Analytics Rules (Phase 3) — one per stage, each with proper MITRE mapping
7. **Critical final step, easy to skip:** once all rules are saved and active, **re-run every attack stage command one more time**
8. Wait one scheduling cycle (rule's configured run frequency, e.g. 5-15 min)
9. Check the **Incidents** tab in Sentinel — screenshot each auto-generated incident

**Why step 7-9 matters more than it seems:** steps 1-6 only prove you can *query* existing logs. Steps 7-9 prove the entire pipeline — Sysmon → AMA → DCR → Sentinel → Analytics Rule → auto-generated Incident — works end-to-end, unattended, exactly like it would in production. **This is your single strongest screenshot set in the whole repo.**

---


