# Automated Response & AI-Assisted Investigation: Scope Notes

This document covers two capabilities that were deliberately **not deployed** in this project — automated response (SOAR) and Microsoft Sentinel's Copilot-assisted investigation features — along with the reasoning behind that decision and what was done instead to demonstrate familiarity with each.

Both are treated the same way here: designed or evaluated at a conceptual level, explicitly scoped out of this iteration for cost and time reasons, and documented honestly as such rather than presented as deployed capabilities.

---

## Automated Response

**Status: Designed, not deployed.**

An automation rule + Logic App playbook design was authored to demonstrate the intended automated response layer, but was not deployed or tested end-to-end in this iteration.

### Intended design

- **Trigger:** Sentinel Automation Rule, condition-free, so it applies to incidents from any of the four analytics rules built in Phase 3
- **Action:** invoke a Logic App playbook
- **Playbook behavior:** send an email notification containing the incident's display name, severity, and description, using dynamic content from the Sentinel incident trigger

### Proposed Logic App definition

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "triggers": {
      "When_incident_created": {
        "type": "ApiConnectionWebhook",
        "inputs": { "body": { "callback_url": "@{listCallbackUrl()}" } }
      }
    },
    "actions": {
      "Send_email_notification": {
        "type": "ApiConnection",
        "inputs": {
          "body": {
            "To": "analyst@example.com",
            "Subject": "Sentinel Incident: @{triggerBody()?['object']?['properties']?['title']}",
            "Body": "Severity: @{triggerBody()?['object']?['properties']?['severity']}"
          }
        }
      }
    }
  }
}
```

### Why this was scoped out

Automation adds real complexity — Logic App authentication, API connection setup, and end-to-end trigger testing — on top of an already substantial detection engineering build. Rather than deploy something without fully validating its failure modes, this was intentionally left as a documented design for a follow-up iteration once the core detection pipeline was solid.

### Planned follow-up

- Deploy and test the playbook above against a live incident
- Extend beyond notification to a containment action (e.g., isolating the VM's NSG on a Persistence-tagged incident), tying the automated response directly back into the network architecture established in Phase 1

---

## Copilot / AI-Assisted Investigation

**Status: Not used.**

Microsoft Sentinel's Copilot and AI-assisted investigation features were not used anywhere in this project. All querying, rule development, and incident triage were performed manually.

### Why this was scoped out

Copilot in Security is a licensed, consumption-based add-on separate from core Sentinel/Log Analytics costs. Given this project was built under a deliberately tight, self-funded cost ceiling (see Phase 1's budget guardrails), it was excluded from scope rather than incurring additional licensing cost for a personal lab.

### What this means for the project

Every KQL query, detection rule, and troubleshooting step documented across Phases 1–4 reflects manual investigation and hand-written query logic — nothing here was AI-generated within the Sentinel platform itself. This was a deliberate choice to build and demonstrate the underlying skill directly, rather than a limitation that had to be worked around.

---

## Summary

| Capability | Status | Reason |
| :--- | :--- | :--- |
| Automated response (SOAR) | Designed, not deployed | Scope/complexity — planned as follow-up |
| Copilot-assisted investigation | Not used | Licensing cost — manual investigation used throughout instead |