# SCCM Patch Compliance & Vulnerability Risk Analytics on Snowflake

An end-to-end analytics project: raw endpoint-management (SCCM-style) extracts -> validated -> modelled in Snowflake -> automated -> reported in Power BI / Tableau.
Built to mirror how a data analyst works in a real operations / IT-governance team.

> **Data note (put this in your public README too):** the dataset is **synthetic**, generated with `generate_sccm_data.py` and cleaned with `clean_sccm_data.py`. It imitates real SCCM data quality problems; it is not client data and its patterns are largely random.

---

## 1. Business problem (write this in your own words)

IT governance must show, every month, **how well servers are patched, where the risk is, and why deployments fail** - today via manual SQL Server extracts and Excel.
Goal: a repeatable, validated pipeline and dashboards that answer:

1. What % of servers are patch-compliant, overall and by environment / severity / business unit?
2. How long do we take to patch, and are we meeting deployment deadlines?
3. Which servers carry the most risk (missing patches x CVSS x known exploit x criticality)?
4. Why do deployments fail, and is any segment (OS, data centre, team, cycle) worse than average?
5. Can we trust the numbers? (data-quality and reconciliation evidence)

**Stakeholders to imagine:** Patch/Change Manager, Security (vulnerability) team, Infrastructure leads, Business-unit owners, Service Delivery Manager.
Write 2-3 "user stories" per stakeholder (e.g. *"As a Security lead I want the servers with exploitable, unpatched CVSS 9+ vulnerabilities so I can prioritise emergency patching."*).

## 2. Architecture

```
Cleaned CSVs (4)          Snowflake  (database SCCM_DB)                                   BI
------------------   ------------------------------------------------------------   -------------
ServerInventory  -->  RAW (as loaded)  -->  CORE (star schema)  -->  MART (views)  -->  Power BI /
PatchingReport   -->  4 tables             DIM_SERVER, DIM_KB,       VW_PATCH_         Tableau
PatchHistory     -->  COPY INTO            DIM_CVE, DIM_DATE         COMPLIANCE
VulnerabilityMap -->                       FACT_PATCH_STATUS         VW_DEPLOYMENT_
                                           FACT_PATCH_DEPLOYMENT     PERFORMANCE
                          |                        |                VW_SERVER_RISK
                          +---- DQ schema: control totals, 27 automated checks, run log
                          +---- ETL schema: stored procedures + scheduled TASK
```

Why layers? RAW keeps an untouched copy (auditability), CORE holds business logic once (single source of truth), MART is what reports read (stable contract for dashboards).

## 3. Step-by-step roadmap (do them in order; each has a checkpoint)

| Step | File | You will learn | Checkpoint before moving on |
|---|---|---|---|
| 0 | - | Create a Snowflake trial account, open Snowsight, know what a warehouse is | You can run `SELECT CURRENT_VERSION();` |
| 1 | `01_setup_and_load.sql` | Warehouses, databases/schemas, stages, file formats, `COPY INTO`, dry-run validation | Counts: 97,000 / 96,990 / 95,509 / 95,737 |
| 2 | `02_eda_profiling.sql` | Null/duplicate/outlier profiling in SQL, window functions, percentiles | 5+ written observations |
| 3 | `03_core_model.sql` | Star schema, surrogate keys, unknown members, KPI flags, stored procedure | Facts have the same row count as their RAW tables |
| 4 | `04_data_quality_checks.sql` | Control totals, reconciliation, rule-based DQ checks | Latest run: 0 FAIL (or you can explain each FAIL) |
| 5 | `05_pipeline_automation.sql` | Stored procedures, error handling, logging, tasks | `CALL ETL.SP_RUN_PIPELINE();` succeeds and logs |
| 6 | `06_mart_views_and_analysis.sql` | Reporting views, CTEs, `LAG`, `QUALIFY`, rolling windows, segment "lift" | Q1 KPI equals Q1b (source reconciliation) |
| 7 | (BI tool) | Dashboards from MART views | 3 dashboards published (see section 5) |
| 8 | (GitHub) | Documentation, ER diagram, findings | Repo passes the checklist in section 7 |

**Beginner rules:** run one statement at a time; read the output; if a number surprises you, investigate before continuing; keep every query you write in the repo.

### Step 0 - Snowflake account
1. Sign up for a Snowflake free trial (30 days with starter credits, as far as I know - check the sign-up page for current terms). Choose **Standard** edition; any cloud/region is fine.
2. Open **Snowsight** -> Projects -> Worksheets -> new SQL worksheet. Confirm the role selector shows `SYSADMIN` (or `ACCOUNTADMIN` on a new trial - `USE ROLE SYSADMIN;` is set in the scripts).
3. **Cost control:** the warehouse is `XSMALL` with `AUTO_SUSPEND = 60`. Suspend any task you resume (`ALTER TASK ... SUSPEND`). This dataset uses a tiny fraction of trial credits.

## 4. KPI dictionary (agree definitions BEFORE building dashboards)

| KPI | Definition | Notes |
|---|---|---|
| Compliance % | Compliant / (Compliant + Non-Compliant) | `Not Applicable` and `Unknown` are excluded from the denominator |
| Overdue record | Status Missing / Failed / Pending **and** `DeploymentDeadline < LastScanDate` | `days_overdue` = scan date - deadline |
| Installed on time | `PatchInstalledDate <= DeploymentDeadline` | Denominator = installed records |
| Days to install | `PatchInstalledDate` - `PatchReleaseDate` (days) | Report median and P90, not just mean |
| Deployment success % | Installed / (Installed + Failed + Rolled Back) | Pending and Skipped are not attempts |
| Server risk score | Sum over missing patches of CVSS x (1.5 if known exploit) x criticality weight (4/3/2/1) | A heuristic - justify or tune it with stakeholders |
| Data-quality pass rate | Passed checks / total checks in the latest DQ run | Also show the failed checks list |

**Documented exclusions:** records with contradictory statuses (`STATUS_CONFLICT`, about 0.7%) are excluded from dashboards; rows with unusable keys were quarantined in the Python step; decommissioned servers are excluded from the risk score.

## 5. Dashboards (build 3; keep each one focused)

**Connecting:** Power BI Desktop (free) has a Snowflake connector: Get Data -> Snowflake -> server = `<account>.snowflakecomputing.com`, warehouse = `SCCM_WH` -> select the three `MART` views. Prefer **Import** for this small dataset. As far as I know, *Tableau Public cannot connect to Snowflake directly*; for Tableau either use a Tableau Desktop trial with the Snowflake connector, or export the MART views to CSV and use Tableau Public.

1. **Executive Patch Compliance** - KPI cards (Compliance %, Overdue records, Servers with overdue patches, DQ pass rate); compliance trend by release month; heat-map Environment x Severity; filters: Environment, Business Unit, Location.
2. **Deployment Performance & Failure Root Cause** - success % by month with rolling average; failure reasons (Pareto); failure rate by OS / data centre / team; average deployment duration by cycle.
3. **Vulnerability & Server Risk** - top 25 servers by risk score; exposed servers by environment (Q12); overdue ageing buckets; drill-through to server detail.

Design checklist: one question per page, KPIs top-left, consistent colours (red = risk), no more than 6-8 visuals, titles state the takeaway, tooltips explain KPI definitions, tested on a filter combination that returns very few rows.

## 6. Findings & documentation you must write

For each of Q1-Q12 in `06_...sql`: **What I asked -> What the data shows -> So what / recommended action -> Caveat.**
Because the data is synthetic, phrase findings as *"in this dataset ..."* and focus on the method. If a segment shows no signal (lift ~ 1), say so - that is a valid, honest finding.

## 7. Portfolio packaging (GitHub)

```
sccm-snowflake-analytics/
  README.md                  <- business problem, architecture, KPI dictionary, findings, screenshots
  data/                      <- sample rows only (first 100 lines of each CSV); note where the full data comes from
  python/generate_sccm_data.py, clean_sccm_data.py
  sql/01_...sql  ...  06_...sql
  docs/data_dictionary.md, erd.png, dq_checks.md, kpi_definitions.md
  dashboards/                <- screenshots + .pbix / .twbx
```
Checklist: architecture diagram - ER diagram - data dictionary - DQ results screenshot - 3 dashboard screenshots - "how to run" section - limitations & next steps - no credentials committed.

## 8. Mapping to your resume bullets - and how to stay honest

The project *demonstrates the skills* behind your bullets. It does **not** prove the numbers in them (20% accuracy gain, 40% faster reporting, 15% savings, etc. come from your real work). Never copy those metrics onto this project.

| Your resume bullet (theme) | Where this project shows the skill | What you can honestly say about it |
|---|---|---|
| Analysed large volumes with SQL, Excel, BI | Steps 2 and 6: profiling, KPIs, windows, segmentation on ~385K rows | "Analysed ~385K synthetic SCCM records across 4 tables" (measure the real count after loading) |
| 15+ interactive dashboards, real-time KPI monitoring | Step 7: 3 dashboards on MART views | "Built 3 dashboards from Snowflake views" - use your real number |
| Extract, transform, validate; data accuracy and fewer discrepancies | Python cleaning + Step 4 control totals, reconciliation, 27 DQ checks | "Implemented N automated DQ checks and reconciled counts source-to-target" (cite N and your latest pass rate) |
| Automated recurring workflows, hours saved | Step 5: one-call pipeline + scheduled task | "Automated the load -> model -> validate flow as stored procedures with run logging" - do not claim hours saved unless you measured them |
| EDA and root-cause investigation | Steps 2, Q9, Q10 | "Used segment lift analysis to test whether failures cluster by OS / data centre / team" |
| Stakeholder requirements -> analytical solutions | Section 1 user stories, KPI dictionary | "Defined KPI logic up front with documented exclusions" |

**Project bullet templates** (fill with real values when done; keep the word *synthetic* in the project description):
- "Designed a Snowflake RAW -> CORE -> MART pipeline (star schema: 4 dimensions, 2 facts) over ~[X]K synthetic SCCM records; full refresh via stored procedures and a scheduled task."
- "Built [N] automated data-quality checks with source-to-target reconciliation and run logging; latest run [P]% pass, [F] failures investigated."
- "Delivered [3] Power BI dashboards covering patch compliance, deployment failure analysis and server risk ranking, on KPI definitions documented in a data dictionary."

## 9. Interview talking points (be ready to explain)
- Why RAW / CORE / MART layers? Why a star schema instead of querying flat files?
- Why keep an *Unknown* dimension member instead of dropping orphan rows?
- How do you know the dashboard KPI is right? (Q1 vs Q1b reconciliation, control totals.)
- Why full refresh here, and how would you move to incremental (streams + MERGE)?
- Which records did you exclude and why? What would you ask the business before deciding?
- Mean vs median vs P90 for time-to-patch - which would you show an executive?

## 10. Common beginner errors
| Symptom | Cause / fix |
|---|---|
| `COPY INTO` returns 0 rows | Files not in the stage yet (`LIST @RAW.STG_SCCM;`) or the `PATTERN` does not match the file name |
| "Number of columns in file does not match" | You uploaded the *raw* CSV instead of the *cleaned* one (cleaned files have `DQ_Flags` as an extra last column) |
| Timestamp conversion error | File format `TIMESTAMP_FORMAT` not applied - re-run the `FILE_FORMAT` and stage statements |
| "Insufficient privileges" on a task | Run the one-time `GRANT EXECUTE TASK ...` as `ACCOUNTADMIN` (see Step 5) |
| Warehouse credits draining | Suspend the task; confirm `AUTO_SUSPEND = 60`; close idle worksheets |
