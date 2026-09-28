
/* ---------------------------------- PART B: ANALYSIS ---------------------------------- */

-- Q1. Executive KPI snapshot. Compliance % = Compliant / (Compliant + Non-Compliant).
SELECT COUNT(*) AS records_in_scope,
       SUM(is_applicable) AS applicable_records,
       ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 2) AS compliance_pct,
       SUM(is_overdue) AS overdue_records,
       COUNT(DISTINCT IFF(is_overdue = 1, ServerID, NULL)) AS servers_with_overdue_patches
FROM MART.VW_PATCH_COMPLIANCE;

-- Q1b. RECONCILE the dashboard number back to the source (do this before you ever publish a KPI)
SELECT ROUND(100 * COUNT_IF(ComplianceStatus = 'Compliant') / NULLIF(COUNT_IF(ComplianceStatus IN ('Compliant', 'Non-Compliant')), 0), 2) AS compliance_pct_from_raw
FROM RAW.PATCHING_REPORT
WHERE NOT CONTAINS(COALESCE(DQ_Flags, ''), 'STATUS_CONFLICT');      -- should equal Q1 compliance_pct

-- Q2. Compliance % by environment x severity (conditional aggregation = a pivot table in SQL)
SELECT Environment,
       ROUND(100 * SUM(IFF(Severity = 'Critical', is_compliant, 0)) / NULLIF(SUM(IFF(Severity = 'Critical',  is_applicable, 0)), 0), 1) AS critical_pct,
       ROUND(100 * SUM(IFF(Severity = 'Important', is_compliant, 0)) / NULLIF(SUM(IFF(Severity = 'Important', is_applicable, 0)), 0), 1) AS important_pct,
       ROUND(100 * SUM(IFF(Severity = 'Moderate', is_compliant, 0)) / NULLIF(SUM(IFF(Severity = 'Moderate',  is_applicable, 0)), 0), 1) AS moderate_pct,
       ROUND(100 * SUM(IFF(Severity = 'Low', is_compliant, 0)) / NULLIF(SUM(IFF(Severity = 'Low',       is_applicable, 0)), 0), 1) AS low_pct,
       ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 1) AS overall_pct
FROM MART.VW_PATCH_COMPLIANCE
GROUP BY Environment
ORDER BY overall_pct;

-- Q3. Compliance trend by patch release month with month-over-month change (LAG window function)
WITH monthly AS (
  SELECT release_month,
         SUM(is_applicable) AS applicable,
         ROUND(100 * SUM(is_compliant) / NULLIF(SUM(is_applicable), 0), 2) AS compliance_pct
  FROM MART.VW_PATCH_COMPLIANCE
  WHERE release_month IS NOT NULL
  GROUP BY release_month
)
SELECT release_month, applicable, compliance_pct, compliance_pct - LAG(compliance_pct) OVER (ORDER BY release_month) AS mom_change_pts
FROM monthly
ORDER BY release_month;

-- Q4. Time-to-patch by severity: mean, median, P90, and % installed on or before the deadline
SELECT Severity,
       COUNT_IF(is_installed = 1) AS installed_records,
       ROUND(AVG(DaysToInstall), 1) AS avg_days_to_install,
       MEDIAN(DaysToInstall) AS median_days,
       PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY DaysToInstall) AS p90_days,
       ROUND(100 * SUM(installed_on_time) / NULLIF(SUM(is_installed), 0), 1) AS pct_installed_on_time
FROM MART.VW_PATCH_COMPLIANCE
WHERE is_installed = 1
GROUP BY Severity
ORDER BY CASE Severity WHEN 'Critical' THEN 1 WHEN 'Important' THEN 2 WHEN 'Moderate' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END;

-- Q5. Top 20 active Production servers by overdue Critical/Important patches
SELECT ServerID, ServerName, BusinessUnit, Location,
       COUNT(*) AS overdue_patches,
       MAX(days_overdue) AS worst_days_overdue
FROM MART.VW_PATCH_COMPLIANCE
WHERE Environment = 'Production' AND ServerStatus = 'Active'
  AND is_overdue = 1 AND Severity IN ('Critical', 'Important')
GROUP BY ServerID, ServerName, BusinessUnit, Location
ORDER BY overdue_patches DESC, worst_days_overdue DESC
LIMIT 20;

-- Q6. Top 3 business units per location by overdue patches (QUALIFY = filter on a window function)
SELECT Location, BusinessUnit, COUNT(*) AS overdue_patches
FROM MART.VW_PATCH_COMPLIANCE
WHERE is_overdue = 1
GROUP BY Location, BusinessUnit
QUALIFY ROW_NUMBER() OVER (PARTITION BY Location ORDER BY COUNT(*) DESC) <= 3
ORDER BY Location, overdue_patches DESC;

-- Q7. Ageing of overdue patches (how bad is the backlog?)
SELECT CASE WHEN days_overdue <= 30  THEN '1) 1-30 days'
            WHEN days_overdue <= 90  THEN '2) 31-90 days'
            WHEN days_overdue <= 180 THEN '3) 91-180 days'
            ELSE '4) 180+ days' END AS overdue_bucket,
       COUNT(*) AS records,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM MART.VW_PATCH_COMPLIANCE
WHERE is_overdue = 1
GROUP BY 1
ORDER BY 1;

-- Q8. Patch-cycle success rate by month + rolling 3-month success rate (window frame)
WITH monthly AS (
  SELECT period_start_date, SUM(is_success) AS successes, SUM(is_attempted) AS attempts
  FROM MART.VW_DEPLOYMENT_PERFORMANCE
  GROUP BY period_start_date
)
SELECT period_start_date, attempts,
       ROUND(100 * successes / NULLIF(attempts, 0), 2) AS success_pct,
       ROUND(100 * SUM(successes) OVER (ORDER BY period_start_date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)
                 / NULLIF(SUM(attempts) OVER (ORDER BY period_start_date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW), 0), 2) AS rolling_3m_success_pct
FROM monthly
ORDER BY period_start_date;

-- Q9. ROOT-CAUSE style analysis: failure reasons and their share within each data centre
SELECT DataCenter, PatchFailureReason,
       COUNT(*) AS failures,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (PARTITION BY DataCenter), 1) AS pct_of_dc_failures
FROM MART.VW_DEPLOYMENT_PERFORMANCE
WHERE is_failure = 1
GROUP BY DataCenter, PatchFailureReason
QUALIFY RANK() OVER (PARTITION BY DataCenter ORDER BY COUNT(*) DESC) <= 3
ORDER BY DataCenter, failures DESC;

-- Q10. Which segment fails MORE than average? "lift" = segment failure rate / overall failure rate.
--      A lift well above 1 with a big sample is a lead worth investigating; lift ~1 = no signal.
WITH base AS (
  SELECT * FROM MART.VW_DEPLOYMENT_PERFORMANCE WHERE is_attempted = 1
),
overall AS (
  SELECT SUM(is_failure) / COUNT(*) AS overall_rate FROM base
),
seg AS (
  SELECT 'OperatingSystem' AS dimension, OperatingSystem AS segment, COUNT(*) AS attempts, SUM(is_failure) AS failures FROM base GROUP BY OperatingSystem
  UNION ALL SELECT 'DataCenter', DataCenter, COUNT(*), SUM(is_failure) FROM base GROUP BY DataCenter
  UNION ALL SELECT 'SupportTeam', SupportTeam, COUNT(*), SUM(is_failure) FROM base GROUP BY SupportTeam
  UNION ALL SELECT 'DeploymentCycle', DeploymentCycle, COUNT(*), SUM(is_failure) FROM base GROUP BY DeploymentCycle
  UNION ALL SELECT 'Environment', Environment, COUNT(*), SUM(is_failure) FROM base GROUP BY Environment
)
SELECT dimension, segment, attempts, failures,
       ROUND(100 * failures / attempts, 2) AS failure_pct,
       ROUND((failures / attempts) / o.overall_rate, 2) AS lift_vs_overall
FROM seg CROSS JOIN overall o
WHERE attempts >= 500                              -- ignore tiny samples
ORDER BY lift_vs_overall DESC
LIMIT 15;

-- Q11. Highest-risk servers (uses VW_SERVER_RISK)
SELECT * FROM MART.VW_SERVER_RISK ORDER BY risk_score DESC LIMIT 25;

-- Q12. Exposure: distinct servers still missing a patch that has a known exploit AND CVSS >= 9, by environment
SELECT Environment, COUNT(DISTINCT ServerID) AS exposed_servers
FROM MART.VW_PATCH_COMPLIANCE
WHERE is_installed = 0 AND PatchStatus IN ('Missing', 'Failed', 'Pending')
  AND has_known_exploit = TRUE AND max_cvss >= 9
GROUP BY Environment
ORDER BY exposed_servers DESC;
