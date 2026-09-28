USE WAREHOUSE SCCM_WH; USE DATABASE SCCM_DB; USE SCHEMA MART;

-- 7.1  VW_KPI_SCORECARD - ONE ROW, the headline numbers for BAN / KPI-card tiles.
--      In Tableau: drag any single measure onto a "Text" mark - no aggregation needed, it's already 1 row.
CREATE OR REPLACE VIEW MART.VW_KPI_SCORECARD AS
WITH compliance AS (
  SELECT COUNT(*) AS total_records,
         SUM(is_applicable) AS applicable_records,
         ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 2)  AS compliance_pct,
         SUM(is_overdue) AS overdue_records,
         COUNT(DISTINCT IFF(is_overdue = 1, ServerID, NULL)) AS servers_with_overdue_patches,
         COUNT(DISTINCT ServerID) AS servers_in_scope,
         ROUND(AVG(IFF(is_installed = 1, DaysToInstall, NULL)), 1) AS avg_days_to_install,
         MEDIAN(IFF(is_installed = 1, DaysToInstall, NULL)) AS median_days_to_install,
         ROUND(100 * SUM(installed_on_time) / NULLIF(SUM(is_installed), 0), 1) AS pct_installed_on_time
  FROM MART.VW_PATCH_COMPLIANCE
),
deployment AS (
  SELECT ROUND(100 * SUM(is_success) / NULLIF(SUM(is_attempted), 0), 2) AS deployment_success_pct,
         SUM(is_failure) AS total_failures,
         ROUND(AVG(IFF(is_success = 1, DeploymentDurationMinutes, NULL)),1) AS avg_deployment_minutes
  FROM MART.VW_DEPLOYMENT_PERFORMANCE
),
exposure AS (
  SELECT COUNT(DISTINCT ServerID) AS exposed_servers_critical_cve
  FROM MART.VW_PATCH_COMPLIANCE
  WHERE is_installed = 0 AND PatchStatus IN ('Missing', 'Failed', 'Pending')
    AND has_known_exploit = TRUE AND max_cvss >= 9
),
DO AS (
  SELECT ROUND(100 * COUNT_IF(STATUS = 'PASS') / NULLIF(COUNT(*), 0), 1)    AS DO_pass_rate_pct,
         COUNT_IF(STATUS = 'FAIL')                                          AS DO_failed_checks,
         MAX(RUN_TS)                                                        AS DO_last_run_ts
  FROM DO.VW_DO_LATEST_RUN
),
refresh AS (
  SELECT MAX(LOG_TS) AS last_pipeline_run_ts
  FROM DO.ETL_RUN_LOG WHERE STEP = 'PIPELINE' AND STATUS IN ('SUCCESS', 'FINISHED_WITH_DO_FAILURES')
)
SELECT c.total_records, c.applicable_records, c.compliance_pct, c.overdue_records,
       c.servers_with_overdue_patches, c.servers_in_scope, c.avg_days_to_install,
       c.median_days_to_install, c.pct_installed_on_time,
       d.deployment_success_pct, d.total_failures, d.avg_deployment_minutes,
       e.exposed_servers_critical_cve,
       q.DO_pass_rate_pct, q.DO_failed_checks, q.DO_last_run_ts,
       r.last_pipeline_run_ts
FROM compliance c CROSS JOIN deployment d CROSS JOIN exposure e CROSS JOIN DO q CROSS JOIN refresh r;

-- 7.2  VW_KPI_MONTHLY_TREND - one row per month, ready for line charts with NO Tableau-side
--      table calcs needed (MoM change is pre-computed).
CREATE OR REPLACE VIEW MART.VW_KPI_MONTHLY_TREND AS
WITH comp_month AS (
  SELECT release_month AS kpi_month,
         SUM(is_applicable) AS applicable_records,
         ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 2) AS compliance_pct
  FROM MART.VW_PATCH_COMPLIANCE
  WHERE release_month IS NOT NULL
  GROUP BY release_month
),
dep_month AS (
  SELECT period_start_date AS kpi_month,
         SUM(is_attempted) AS attempts,
         ROUND(100 * SUM(is_success) / NULLIF(SUM(is_attempted), 0), 2) AS success_pct
  FROM MART.VW_DEPLOYMENT_PERFORMANCE
  GROUP BY period_start_date
)
SELECT COALESCE(c.kpi_month, d.kpi_month) AS kpi_month,
       c.applicable_records, c.compliance_pct,
       c.compliance_pct - LAG(c.compliance_pct) OVER (ORDER BY c.kpi_month)   AS compliance_mom_change_pts,
       d.attempts, d.success_pct,
       ROUND(100 * SUM(d.attempts * d.success_pct / 100) OVER (ORDER BY d.kpi_month ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)/ NULLIF(SUM(d.attempts) OVER (ORDER BY d.kpi_month ROWS BETWEEN 2 PRECEDING AND CURRENT ROW), 0), 2) AS success_rolling_3m_pct
FROM comp_month c
FULL OUTER JOIN dep_month d ON d.kpi_month = c.kpi_month
ORDER BY 1;

-- 7.3  VW_KPI_BY_SEGMENT - pre-built breakdowns for the segments you ask about most (Environment,
--      Severity, BusinessUnit). Use VW_PATCH_COMPLIANCE directly in Tableau instead if you need a
--      segment not listed here - that view supports ANY breakdown live.
CREATE OR REPLACE VIEW MART.VW_KPI_BY_SEGMENT AS
SELECT 'Environment' AS segment_type, Environment AS segment_value,
       SUM(is_applicable) AS applicable_records,
       ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 2) AS compliance_pct,
       SUM(is_overdue) AS overdue_records
FROM MART.VW_PATCH_COMPLIANCE GROUP BY Environment
UNION ALL
SELECT 'Severity', Severity,
       SUM(is_applicable),
       ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 2),
       SUM(is_overdue)
FROM MART.VW_PATCH_COMPLIANCE GROUP BY Severity
UNION ALL
SELECT 'BusinessUnit', BusinessUnit,
       SUM(is_applicable),
       ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 2),
       SUM(is_overdue)
FROM MART.VW_PATCH_COMPLIANCE GROUP BY BusinessUnit;

-- CHECKPOINT: all three should return data (scorecard = 1 row; the others = many rows)
SELECT * FROM MART.VW_KPI_SCORECARD;
SELECT * FROM MART.VW_KPI_MONTHLY_TREND ORDER BY kpi_month;
SELECT * FROM MART.VW_KPI_BY_SEGMENT ORDER BY segment_type, compliance_pct;