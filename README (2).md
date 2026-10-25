# Microsoft Sentinel Cloud SOC Lab

![Azure](https://img.shields.io/badge/Cloud-Microsoft%20Azure-0078D4?logo=microsoftazure&logoColor=white)
![Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4)
![KQL](https://img.shields.io/badge/Language-KQL-5C2D91)
![Type](https://img.shields.io/badge/Type-Personal%20Learning%20Lab-lightgrey)

A beginner-friendly cloud security monitoring lab built on **Microsoft Azure**. It collects **Azure Activity logs** into a **Log Analytics workspace**, uses **Microsoft Sentinel** as the SIEM, investigates failed operations with **Kusto Query Language (KQL)**, and implements a **scheduled analytics rule** that flags repeated failures by the same caller.

> **Scope note:** this is a personal learning lab, not a production SOC deployment. It covers Azure control-plane activity only (see [Limitations](#limitations)).

---

## Table of contents

1. [Project objective](#project-objective)
2. [Architecture](#architecture)
3. [Lab environment](#lab-environment)
4. [Walkthrough](#walkthrough)
   - [Step 1 – Azure subscription](#step-1--azure-subscription)
   - [Step 2 – Log Analytics workspace and Sentinel](#step-2--log-analytics-workspace-and-sentinel)
   - [Step 3 – Connect Azure Activity logs](#step-3--connect-azure-activity-logs)
   - [Step 4 – Validate log collection](#step-4--validate-log-collection)
   - [Step 5 – Investigate failed operations with KQL](#step-5--investigate-failed-operations-with-kql)
   - [Step 6 – Create the detection rule](#step-6--create-the-detection-rule)
   - [Step 7 – Alert and incident review](#step-7--alert-and-incident-review)
5. [KQL reference](#kql-reference)
6. [Findings and lessons learned](#findings-and-lessons-learned)
7. [Limitations](#limitations)
8. [Possible improvements](#possible-improvements)
9. [Cost and clean-up](#cost-and-clean-up)
10. [Skills demonstrated](#skills-demonstrated)
11. [Repository structure](#repository-structure)

---

## Project objective

The goals of this lab were to:

- Collect **Azure Activity logs** from a subscription into a Log Analytics workspace.
- Use **KQL** to search for failed operations and read who did what, when, and where.
- Configure a simple **scheduled detection rule** for three or more failed operations by the same caller within a 15-minute window.
- Practise the analyst workflow: review an alert, check timestamp / caller / operation / context, and document the outcome, including the case where no alert fires.

## Architecture

```
Azure activity  ──►  Log Analytics workspace  ──►  Microsoft Sentinel  ──►  SOC analyst review
(Activity logs)      (stores AzureActivity)        (analytics rules,         (KQL, alerts, incidents,
                                                    incidents)                documentation)
```

| Component | Role in this lab |
|---|---|
| **Azure Activity logs** | Source events: control-plane operations on the subscription (create, update, delete, deployments, role/policy assignments). |
| **Log Analytics workspace** | Stores the data in searchable tables, here `AzureActivity`. |
| **Microsoft Sentinel** | Cloud-native SIEM: data connectors, analytics rules, incidents. |
| **Analyst (me)** | Runs KQL, reviews alerts, documents findings. |

![Architecture diagram](images/07-architecture-diagram.png)

## Lab environment

| Item | Value |
|---|---|
| Cloud platform | Microsoft Azure (free-credit subscription, `Owner` role) |
| Resource group | `rg-sentinel-cloudsoc` |
| Log Analytics workspace | `law-sentinel-cloudsoc` |
| Region | South India |
| Workspace pricing tier | Pay-as-you-go |
| Access control mode | Use resource or workspace permissions |
| Sentinel content | *Azure Activity* solution from the Content hub |
| Detection rule | `Repeated Failed Azure Operations` (Scheduled, Medium severity) |

> Subscription ID, tenant/directory details, workspace ID, rule ID and account email were removed or blacked out of the screenshots in this repository.

## Walkthrough

### Step 1 – Azure subscription

I used a personal Azure subscription with free credit and the `Owner` role. Cost analysis showed no spend at the time of capture.

![Azure subscription overview](images/01-subscription-overview.png)

### Step 2 – Log Analytics workspace and Sentinel

I created the resource group `rg-sentinel-cloudsoc` and the Log Analytics workspace `law-sentinel-cloudsoc` in South India, then enabled Microsoft Sentinel on that workspace. The workspace overview shows an active status and no operational issues.

![Log Analytics workspace overview](images/02-log-analytics-workspace.png)

### Step 3 – Connect Azure Activity logs

From **Sentinel → Content hub** I used the **Azure Activity solution for Sentinel**, which ships the data connector plus related workbooks, analytics rule templates and hunting queries, so that subscription activity is sent to the workspace.

![Azure Activity solution in the Content hub](images/03-content-hub-azure-activity-solution.png)

The resource group's own Activity log records the setup operations as they happened (deployments, creation of the OMS solution, a role assignment, a policy assignment, onboarding-state updates and alert-rule updates). This is useful as a timeline of the build, and it also shows the kind of events the `AzureActivity` table is meant to hold.

![Resource group activity log](images/04-resource-group-activity-log.png)

### Step 4 – Validate log collection

To check that data was reaching the workspace I queried the `AzureActivity` table in **Sentinel → Logs**:

```kusto
AzureActivity
| where TimeGenerated > ago(2h)
| project TimeGenerated, OperationNameValue,
          ActivityStatusValue, Caller, ResourceGroup
| order by TimeGenerated desc
```

**Result:** this first query returned *"No results found from the specified time range"* for the last two hours.

![KQL validation query](images/05-kql-validation-query.png)

<!-- TODO (author): re-run this query after ingestion has caught up (try ago(24h) or ago(7d)),
     replace images/05-kql-validation-query.png with a screenshot showing rows, and update the result above. -->

How I read this: the connector had only just been configured, and newly connected sources can take a while before records appear in the workspace. An empty result at that moment is not proof the connector is broken, but it also does not prove ingestion works. Validation is only complete once the table returns rows, so the next check is to widen the time range and re-run the query.

### Step 5 – Investigate failed operations with KQL

Once records are present, this query surfaces failed operations with the fields an analyst needs first: when, who, what, and where.

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatusValue =~ "Failure"
| project TimeGenerated, Caller, OperationNameValue,
          ResourceGroup, ActivityStatusValue
| order by TimeGenerated desc
```

A failed operation is **not automatically malicious**. Typical benign causes include missing permissions, a typo in a resource name, a policy that blocks a deployment, or a quota limit. The analyst's job is to look at context: who the caller is, whether it is a person or a service principal, whether the pattern is new, and what resource was targeted.

### Step 6 – Create the detection rule

I created a **scheduled analytics rule** named **Repeated Failed Azure Operations**.

| Setting | Value |
|---|---|
| Rule type | Scheduled |
| Severity | Medium |
| Status | Enabled |
| Source | Custom content |
| Query frequency | Every 1 hour |
| Lookback period | Last 1 hour |

Rule logic: flag any caller with **three or more failed operations in a 15-minute bucket**.

```kusto
AzureActivity
| where TimeGenerated > ago(15m)
| where ActivityStatusValue =~ "Failure"
| summarize FailureCount = count() by Caller, bin(TimeGenerated, 15m)
| where FailureCount >= 3
```

![Analytics rule in Sentinel](images/06-analytics-rule-repeated-failed-operations.png)

> The rule is shown in the unified Microsoft Defender portal, where Sentinel is now surfaced alongside other security tools.

### Step 7 – Alert and incident review

When a rule fires, the review routine I practised is:

1. Open the incident / alert and note the **timestamp** and the 15-minute window.
2. Identify the **caller** and whether it is an expected user or service principal.
3. List the **operations** and **resource groups** involved, and whether they are related.
4. Check the surrounding Activity log for **context** (what else did this caller do before and after?).
5. Classify the outcome (benign / needs follow-up / suspicious) and **document the reasoning**.

**Outcome in this lab:** the environment is a single-user lab, so there were no matching bursts of failures during the test window, and no incident from this rule is shown in the captured evidence. Documenting a "no alert" result and why is itself part of the exercise.

## KQL reference

| Purpose | Query |
|---|---|
| View recent logs | `AzureActivity \| take 20` |
| Find failed operations | See [Step 5](#step-5--investigate-failed-operations-with-kql) |
| Repeated failures (detection logic) | See [Step 6](#step-6--create-the-detection-rule) |

## Findings and lessons learned

**What worked**

- Standing up the full chain: resource group → Log Analytics workspace → Sentinel → Azure Activity solution → custom scheduled rule.
- Writing KQL that projects the fields needed for triage (time, caller, operation, resource group, status).
- Expressing the detection as a simple, explainable aggregation: count of failures per caller per 15-minute bin, filtered at a threshold.

**What I learned**

- **Validate the pipeline before trusting a detection.** My first validation query returned nothing; a rule built on an empty table cannot fire, so confirming ingestion comes first.
- **Rule schedule and query window should line up.** My rule runs every hour with a one-hour lookback, but the query itself only looks at the last 15 minutes, so it would only ever inspect the final quarter of each run's window. The query time filter and the rule's lookback/frequency should be designed together (see [Possible improvements](#possible-improvements)).
- **Failure ≠ malicious.** Activity-log failures are mostly operational noise; detections need context and tuning.
- **Portal Activity log vs. workspace table.** The Azure portal's Activity log and the `AzureActivity` table are different views, and data reaches the table only after the connector is working.

## Limitations

- Covers **Azure Activity logs only** (control-plane operations). It does not demonstrate Windows endpoint monitoring, malware detection, identity sign-in analysis, or detection of real attacks. Those need additional data sources and testing.
- The detection rule has **not been validated with deliberately generated test events**, so its alerting behaviour is unproven.
- The rule has **no entity mapping, MITRE ATT&CK mapping, or automated response** configured.
- Single-user, single-subscription lab with no realistic background traffic.

## Possible improvements

1. **Fix the query window.** Remove the hard-coded `ago(15m)` filter and let the rule's lookback define the window, or set the frequency and lookback to 15 minutes. For example (not yet deployed in this lab):

   ```kusto
   AzureActivity
   | where ActivityStatusValue =~ "Failure"
   | summarize FailureCount = count(),
               Operations = make_set(OperationNameValue, 10),
               ResourceGroups = make_set(ResourceGroup, 10)
               by Caller, bin(TimeGenerated, 15m)
   | where FailureCount >= 3
   ```
2. **Test the rule on purpose.** Generate three or more failing operations from one account within 15 minutes (for example, repeated deployments of an intentionally invalid template) and document the resulting alert end to end.
3. **Add entity mapping** (account) and enrich the alert with the operation and resource-group lists.
4. **Add more data sources**, such as Microsoft Entra ID sign-in logs, then build cross-source detections.
5. **Add a workbook** to visualise failures over time by caller and operation.
6. **Try an automation rule or playbook** to enrich or notify on incident creation.

## Cost and clean-up

- This lab used an Azure free-credit subscription. Microsoft Sentinel has offered a free trial for new workspaces, but terms change, so **check current pricing** and set a budget alert in Cost Management.
- When you are finished, delete everything created by the lab in one step, which removes the workspace and Sentinel data with it:

  ```bash
  az group delete --name rg-sentinel-cloudsoc --yes --no-wait
  ```

## Skills demonstrated

Azure resource organisation · Log Analytics workspace setup · Microsoft Sentinel onboarding · data connector / Content hub usage · KQL querying and aggregation · scheduled analytics rule design · alert triage workflow · security documentation and redaction of sensitive data.

## Repository structure

```
.
├── README.md
└── images/
    ├── 01-subscription-overview.png
    ├── 02-log-analytics-workspace.png
    ├── 03-content-hub-azure-activity-solution.png
    ├── 04-resource-group-activity-log.png
    ├── 05-kql-validation-query.png
    ├── 06-analytics-rule-repeated-failed-operations.png
    └── 07-architecture-diagram.png
```

---

**Tools:** Microsoft Azure · Microsoft Sentinel · Log Analytics · Azure Activity logs · KQL

**Author:** _add your name and LinkedIn link here_

_Disclaimer: educational project. Screenshots have had account, tenant and subscription identifiers removed._
