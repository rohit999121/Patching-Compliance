USE WAREHOUSE SCCM_WH; USE DATABASE SCCM_DB; USE SCHEMA MART;

CREATE OR REPLACE VIEW MART.VW_PATCH_COMPLIANCE AS
SELECT f.RecordID, f.ServerID, s.ServerName, s.Environment, s.BusinessUnit, s.Location, s.DataCenter,
       s.OperatingSystem, s.ServerCriticality, s.ServerType, s.SupportTeam, s.CurrentStatus AS ServerStatus,
       k.KBNumber, k.PatchCategory, k.Severity, k.max_cvss, k.has_known_exploit,
       d.year_month AS release_year_month, d.cal_year AS release_year, d.cal_quarter AS release_quarter,
       DATE_TRUNC('month', f.PatchReleaseDate) AS release_month,
       f.PatchStatus, f.ComplianceStatus, f.DeploymentStatus, f.DeploymentName, f.PatchSource, f.RebootRequired,
       f.PatchReleaseDate, f.PatchInstalledDate, f.LastScanDate, f.DeploymentDeadline,
       f.DaysSincePatch, f.DaysToInstall,
       f.is_applicable, f.is_compliant, f.is_installed, f.installed_on_time, f.is_overdue,
       IFF(f.is_overdue = 1, DATEDIFF('day', f.DeploymentDeadline, f.LastScanDate), NULL) AS days_overdue,
       f.is_orphan_server
FROM CORE.FACT_PATCH_STATUS f
JOIN CORE.DIM_SERVER s ON s.server_key = f.server_key
JOIN CORE.DIM_KB k ON k.kb_key = f.kb_key
LEFT JOIN CORE.DIM_DATE d ON d.date_key = f.release_date_key
WHERE f.has_status_conflict = 0;


-- A2. Deployment performance (one row per deployment attempt)
CREATE OR REPLACE VIEW MART.VW_DEPLOYMENT_PERFORMANCE AS
SELECT h.HistoryID, h.ServerID, s.ServerName, s.Environment, s.Location, s.DataCenter, s.OperatingSystem,
       s.ServerCriticality, s.SupportTeam, k.Severity, k.PatchCategory,
       h.PatchYear, h.PatchMonth, h.period_start_date, TO_CHAR(h.period_start_date, 'YYYY-MM') AS period,
       h.DeploymentCycle, h.PatchStatus, h.DeploymentStatus, h.DeploymentDurationMinutes, h.RebootRequired,
       h.PatchFailureReason, h.DaysToCompliance, h.is_attempted, h.is_success, h.is_failure
FROM CORE.FACT_PATCH_DEPLOYMENT h
JOIN CORE.DIM_SERVER s ON s.server_key = h.server_key
JOIN CORE.DIM_KB k ON k.kb_key = h.kb_key
WHERE h.has_status_conflict = 0;


--     A3. Server risk ranking. risk_score is a SIMPLE heuristic you define with stakeholders:
--     sum(CVSS x 1.5 if a known exploit exists) over missing patches, x criticality weight (4/3/2/1).
CREATE OR REPLACE VIEW MART.VW_SERVER_RISK AS
SELECT s.ServerID, s.ServerName, s.Environment, s.BusinessUnit, s.Location, s.ServerCriticality,
       COUNT(*) AS open_patches,
       SUM(f.is_overdue) AS overdue_patches,
       SUM(IFF(k.has_known_exploit, 1, 0)) AS open_patches_with_known_exploit,
       MAX(k.max_cvss) AS max_cvss_exposed,
       ROUND(SUM(COALESCE(k.max_cvss, 0) * IFF(k.has_known_exploit, 1.5, 1.0))
             * CASE s.ServerCriticality WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END, 1) AS risk_score
FROM CORE.FACT_PATCH_STATUS f
JOIN CORE.DIM_SERVER s ON s.server_key = f.server_key
JOIN CORE.DIM_KB     k ON k.kb_key     = f.kb_key
WHERE f.PatchStatus IN ('Missing', 'Failed', 'Pending')
  AND f.has_status_conflict = 0
  AND s.server_key <> -1
  AND s.CurrentStatus <> 'Decommissioned'
GROUP BY s.ServerID, s.ServerName, s.Environment, s.BusinessUnit, s.Location, s.ServerCriticality;

CREATE OR REPLACE VIEW RPT_PATCH_COMPLIANCE AS


select * from VW_SERVER_RISK