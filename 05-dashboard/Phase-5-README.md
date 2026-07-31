# Phase 5: Detection Dashboard

This phase consolidates the detection coverage built across Phases 1–4 into a single Sentinel Workbook — a visual summary intended to let anyone reviewing the project see the full scope of what's being monitored and detected without reading through every individual query or rule.

## Purpose

Individual analytics rules and incident queues demonstrate that detection works; a dashboard demonstrates *coverage* at a glance. This workbook was built as the single visual entry point into the project's detection capability — the artifact most useful for a quick review, versus the individual phase documentation being more useful for a detailed technical read-through.

## Dashboard: SOC-Capstone-Attack-Detection-Dashboard

**Description (as displayed in the workbook):** *Detection coverage across a simulated attack chain: initial execution, persistence, and discovery. Built on dual telemetry sources (Windows Security auditing + Sysmon), mapped to MITRE ATT&CK.*

<img src="./screenshots/workbook-dashboard-final.png" alt="SOC Capstone Attack Detection Dashboard" width="850" style="max-width:100%; height:auto; display:block; margin:10px 0; border:1px solid #ddd; border-radius:4px;"/>

### What the dashboard shows

**Table volume overview:** a bar chart summarizing record counts across the core tables the project relies on — `Event` (Sysmon), `SecurityEvent` (Windows auditing), `Heartbeat` (agent health), `SecurityAlert`, `SecurityIncident`, `Usage`, and `Operation` — giving an immediate sense of where telemetry volume is concentrated and confirming both primary log sources are actively populated.

**Stage 3 — Discovery Commands (count by command type):** a table breaking down the discovery sequence by individual command (`whoami.exe`, `net.exe`, `systeminfo.exe`, `tasklist.exe`) with counts and timestamps, giving a more granular view than the aggregate detection rule alone provides.

### Design notes

The workbook deliberately favors a small number of high-signal visuals over a comprehensive tile-per-rule layout. A table-volume chart plus a discovery-command breakdown was judged sufficient to demonstrate both pipeline health (are both log sources flowing) and detection specificity (can individual techniques within a stage be distinguished from one another), without requiring a reader to parse a dozen near-identical panels.

## How it was built

1. Microsoft Sentinel → Workbooks → **+ New**
2. Added a Markdown/Text step for the title and description
3. Added query steps for each visualization, using the same KQL patterns documented in Phase 3, with `render timechart` or default table visualization depending on the panel
4. Saved as `SOC-Capstone-Attack-Detection-Dashboard`

## Phase 5 Completion Criteria

**Phase 5 is considered complete when:**

1. A workbook exists consolidating detection coverage across all four Phase 3 rules.
2. The workbook confirms both telemetry sources (Sysmon and Windows Security auditing) are actively populated.
3. At least one panel demonstrates detection specificity at the individual-technique level, not just aggregate volume.
4. The workbook is saved and screenshotted as the project's primary visual summary artifact.

---

***Phase 5 is the last phase of the core detection engineering build. Automated response and AI-assisted investigation were intentionally scoped out of this iteration — see the automation design notes for details.***