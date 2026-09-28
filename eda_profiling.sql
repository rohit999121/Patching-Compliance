USE WAREHOUSE SCCM_WH; USE DATABASE SCCM_DB; USE SCHEMA RAW;

-- 2.1  Null profile (completeness). COUNT(col) ignores NULLs, COUNT(*) does not.
SELECT COUNT(*)AS total_rows,
       ROUND(100 * (COUNT(*) - COUNT(IPAddress))/ COUNT(*), 2) AS ip_null_pct,
       ROUND(100 * (COUNT(*) - COUNT(MemoryGB))/ COUNT(*), 2) AS memory_null_pct,
       ROUND(100 * (COUNT(*) - COUNT(DiskSpaceGB))/ COUNT(*), 2) AS disk_null_pct
FROM RAW.SERVER_INVENTORY;

SELECT COUNT(*)AS total_rows,
       ROUND(100 * COUNT_IF(PatchInstalledDate IS NULL) / COUNT(*), 2) AS installed_date_null_pct,
       ROUND(100 * COUNT_IF(LastScanDate IS NULL)/ COUNT(*), 2) AS scan_date_null_pct,
       ROUND(100 * COUNT_IF(RebootRequired IS NULL)/ COUNT(*), 2) AS reboot_null_pct
FROM RAW.PATCHING_REPORT;

-- 2.2  Category distributions with % share (window function over the whole result)
SELECT Environment, COUNT(*) AS servers,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM RAW.SERVER_INVENTORY GROUP BY Environment ORDER BY servers DESC;

SELECT PatchStatus, ComplianceStatus, COUNT(*) AS records,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM RAW.PATCHING_REPORT GROUP BY 1, 2 ORDER BY records DESC;

SELECT Severity, COUNT(*) AS records
FROM RAW.PATCHING_REPORT GROUP BY Severity ORDER BY records DESC;

-- 2.3  Numeric summary: min / max / mean / median / std-dev / percentiles
SELECT MIN(DaysToInstall)AS min_days,
       ROUND(AVG(DaysToInstall), 1)AS avg_days,
       MEDIAN(DaysToInstall)AS median_days,
       ROUND(STDDEV(DaysToInstall), 1)AS stddev_days,
       PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY DaysToInstall) AS p90_days,
       PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY DaysToInstall) AS p99_days,
       MAX(DaysToInstall)AS max_days
FROM RAW.PATCHING_REPORT WHERE DaysToInstall IS NOT NULL;

-- 2.4  Outliers with the IQR rule (value > Q3 + 1.5*IQR). Same idea you would use in pandas.
WITH q AS (
  SELECT PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY DaysToInstall) AS q1,
         PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY DaysToInstall) AS q3
  FROM RAW.PATCHING_REPORT WHERE DaysToInstall IS NOT NULL
)
SELECT q.q1, q.q3, q.q3 + 1.5 * (q.q3 - q.q1) AS upper_fence,
       COUNT_IF(p.DaysToInstall > q.q3 + 1.5 * (q.q3 - q.q1)) AS outlier_rows
FROM RAW.PATCHING_REPORT p CROSS JOIN q
GROUP BY q.q1, q.q3;

-- 2.5  Uniqueness / duplicate checks on business keys (expect 0 rows returned)
SELECT ServerID, COUNT(*) FROM RAW.SERVER_INVENTORY GROUP BY ServerID HAVING COUNT(*) > 1;
SELECT KBNumber, CVEID, COUNT(*) FROM RAW.VULNERABILITY_MAPPING GROUP BY 1, 2 HAVING COUNT(*) > 1;

-- 2.6  Referential integrity: patch rows whose server is not in inventory (orphans)
SELECT COUNT(*) AS orphan_rows
FROM RAW.PATCHING_REPORT p
WHERE NOT EXISTS (SELECT 1 FROM RAW.SERVER_INVENTORY s WHERE s.ServerID = p.ServerID);

-- 2.7  Which data-quality flags did the Python cleaning step leave behind?
--      SPLIT_TO_TABLE turns 'FLAG_A;FLAG_B' into one row per flag.
SELECT f.VALUE::VARCHAR AS dq_flag, COUNT(*) AS rows_affected
FROM RAW.PATCHING_REPORT p, LATERAL SPLIT_TO_TABLE(p.DQ_Flags, ';') f
WHERE p.DQ_Flags IS NOT NULL
GROUP BY 1 ORDER BY rows_affected DESC;

-- 2.8  Time coverage: how many patch records per release month?
SELECT DATE_TRUNC('month', PatchReleaseDate) AS release_month, COUNT(*) AS records
FROM RAW.PATCHING_REPORT WHERE PatchReleaseDate IS NOT NULL
GROUP BY 1 ORDER BY 1;

-- 2.9  Relationship check: does exploit availability rise with CVSS score? (sanity check on the data)
SELECT ExploitAvailable, COUNT(*) AS cves, ROUND(AVG(CVSSScore), 2) AS avg_cvss
FROM RAW.VULNERABILITY_MAPPING GROUP BY ExploitAvailable ORDER BY avg_cvss DESC;

-- 2.10 Failure reasons in patch history
SELECT PatchFailureReason, COUNT(*) AS failures,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM RAW.PATCH_HISTORY
WHERE PatchStatus IN ('Failed', 'Rolled Back')
GROUP BY 1 ORDER BY failures DESC;
