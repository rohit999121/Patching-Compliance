USE WAREHOUSE SCCM_WH; USE DATABASE SCCM_DB; USE SCHEMA DO;

CREATE OR REPLACE TABLE DO.SOURCE_CONTROL_TOTALS (
  TABLE_NAME          VARCHAR(50),
  RAW_ROWS_EXTRACTED  NUMBER,   -- rows in the raw SCCM extract
  DUPLICATES_REMOVED  NUMBER,   -- exact + older versions of the same key
  ROWS_QUARANTINED    NUMBER,   -- unusable keys, sent to rejects/
  EXPECTED_CLEAN_ROWS NUMBER    -- = raw - duplicates - quarantined
);

INSERT INTO DO.SOURCE_CONTROL_TOTALS VALUES
  ('SERVER_INVENTORY', 100000, 3000,    0, 97000),
  ('PATCHING_REPORT', 100000, 3000,   10, 96990),
  ('PATCH_HISTORY', 100000, 2941, 1550, 95509),
  ('VULNERABILITY_MAPPING', 100000, 2955, 1308, 95737);


  select * from SOURCE_CONTROL_TOTALS

SELECT * FROM DO.SOURCE_CONTROL_TOTALS
WHERE RAW_ROWS_EXTRACTED - DUPLICATES_REMOVED - ROWS_QUARANTINED <> EXPECTED_CLEAN_ROWS;

CREATE TABLE IF NOT EXISTS DO.CHECK_RESULTS (
  RUN_ID     VARCHAR(50),
  RUN_TS     TIMESTAMP_NTZ,
  LAYER      VARCHAR(10),
  TABLE_NAME VARCHAR(50),
  CHECK_NAME VARCHAR(100),
  OPERATOR   VARCHAR(2),          -- '=' or '<='
  THRESHOLD  NUMBER(18,4),        -- allowed value
  ACTUAL     NUMBER(18,4),        -- measured value (a difference, a violation count, or a % )
  STATUS     VARCHAR(4)           -- PASS / FAIL
);

CREATE TABLE IF NOT EXISTS DO.ETL_RUN_LOG (
  LOG_TS   TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
  RUN_ID   VARCHAR(50),
  STEP     VARCHAR(50),
  STATUS   VARCHAR(30),
  MESSAGE  VARCHAR(2000)
);

-- (c) THE CHECK RUNNER ---------------------------------------------------------------------
-- Every branch of the UNION ALL returns: layer, table, check name, operator, threshold, actual.
-- The outer query decides PASS/FAIL, so adding a new rule = adding one more SELECT.
CREATE OR REPLACE PROCEDURE DO.SP_RUN_DO_CHECKS(P_RUN_ID VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
  INSERT INTO DO.CHECK_RESULTS (RUN_ID, RUN_TS, LAYER, TABLE_NAME, CHECK_NAME, OPERATOR, THRESHOLD, ACTUAL, STATUS)
  WITH checks AS (

    -- 1. RECONCILIATION: rows loaded minus rows expected (must be 0) ---------------------------
    SELECT 'RAW' AS layer, 'SERVER_INVENTORY' AS tbl, 'ROW_COUNT_MINUS_EXPECTED' AS chk, '=' AS op, 0 AS thr,
           (SELECT COUNT(*) FROM RAW.SERVER_INVENTORY)
         - (SELECT EXPECTED_CLEAN_ROWS FROM DO.SOURCE_CONTROL_TOTALS WHERE TABLE_NAME = 'SERVER_INVENTORY') AS actual
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'ROW_COUNT_MINUS_EXPECTED', '=', 0,
           (SELECT COUNT(*) FROM RAW.PATCHING_REPORT)
         - (SELECT EXPECTED_CLEAN_ROWS FROM DO.SOURCE_CONTROL_TOTALS WHERE TABLE_NAME = 'PATCHING_REPORT')
    UNION ALL SELECT 'RAW', 'PATCH_HISTORY', 'ROW_COUNT_MINUS_EXPECTED', '=', 0,
           (SELECT COUNT(*) FROM RAW.PATCH_HISTORY)
         - (SELECT EXPECTED_CLEAN_ROWS FROM DO.SOURCE_CONTROL_TOTALS WHERE TABLE_NAME = 'PATCH_HISTORY')
    UNION ALL SELECT 'RAW', 'VULNERABILITY_MAPPING', 'ROW_COUNT_MINUS_EXPECTED', '=', 0,
           (SELECT COUNT(*) FROM RAW.VULNERABILITY_MAPPING)
         - (SELECT EXPECTED_CLEAN_ROWS FROM DO.SOURCE_CONTROL_TOTALS WHERE TABLE_NAME = 'VULNERABILITY_MAPPING')

    -- 2. UNIQUENESS of primary keys (duplicated key values must be 0) -------------------------
    UNION ALL SELECT 'RAW', 'SERVER_INVENTORY', 'DUPLICATE_PK', '=', 0,
           (SELECT COUNT(*) - COUNT(DISTINCT ServerID) FROM RAW.SERVER_INVENTORY)
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'DUPLICATE_PK', '=', 0,
           (SELECT COUNT(*) - COUNT(DISTINCT RecordID) FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'RAW', 'PATCH_HISTORY', 'DUPLICATE_PK', '=', 0,
           (SELECT COUNT(*) - COUNT(DISTINCT HistoryID) FROM RAW.PATCH_HISTORY)
    UNION ALL SELECT 'RAW', 'VULNERABILITY_MAPPING', 'DUPLICATE_PK', '=', 0,
           (SELECT COUNT(*) - COUNT(DISTINCT KBNumber || '|' || CVEID) FROM RAW.VULNERABILITY_MAPPING)

    -- 3. COMPLETENESS of keys -------------------------------------------------------------------
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'NULL_KEYS', '=', 0,
           (SELECT COUNT_IF(ServerID IS NULL OR KBNumber IS NULL) FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'RAW', 'PATCH_HISTORY', 'NULL_KEYS', '=', 0,
           (SELECT COUNT_IF(ServerID IS NULL OR KBNumber IS NULL) FROM RAW.PATCH_HISTORY)

    -- 4. NO FAN-OUT: joins to dimensions must not change the fact row count -------------------------
    UNION ALL SELECT 'CORE', 'FACT_PATCH_STATUS', 'ROWS_MINUS_RAW', '=', 0,
           (SELECT COUNT(*) FROM CORE.FACT_PATCH_STATUS) - (SELECT COUNT(*) FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'CORE', 'FACT_PATCH_DEPLOYMENT', 'ROWS_MINUS_RAW', '=', 0,
           (SELECT COUNT(*) FROM CORE.FACT_PATCH_DEPLOYMENT) - (SELECT COUNT(*) FROM RAW.PATCH_HISTORY)

    -- 5. REFERENTIAL INTEGRITY (% of fact rows that point to the Unknown / missing member) -------------
    UNION ALL SELECT 'CORE', 'FACT_PATCH_STATUS', 'ORPHAN_SERVER_PCT', '<=', 1,
           (SELECT ROUND(100 * COUNT_IF(server_key = -1) / COUNT(*), 4) FROM CORE.FACT_PATCH_STATUS)
    UNION ALL SELECT 'CORE', 'FACT_PATCH_DEPLOYMENT', 'ORPHAN_SERVER_PCT', '<=', 1,
           (SELECT ROUND(100 * COUNT_IF(server_key = -1) / COUNT(*), 4) FROM CORE.FACT_PATCH_DEPLOYMENT)
    UNION ALL SELECT 'CORE', 'FACT_PATCH_STATUS', 'KB_WITHOUT_CVE_PCT', '<=', 1,
           (SELECT ROUND(100 * COUNT_IF(k.cve_count = 0) / COUNT(*), 4)
              FROM CORE.FACT_PATCH_STATUS f JOIN CORE.DIM_KB k ON k.kb_key = f.kb_key)

    -- 6. VALID VALUES (accepted-value lists; violations must be 0) ---------------------------------
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'INVALID_PATCHSTATUS', '=', 0,
           (SELECT COUNT_IF(PatchStatus NOT IN ('Installed','Missing','Failed','Pending','Not Applicable','Unknown'))
              FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'INVALID_COMPLIANCESTATUS', '=', 0,
           (SELECT COUNT_IF(ComplianceStatus NOT IN ('Compliant','Non-Compliant','Not Applicable','Unknown'))
              FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'INVALID_SEVERITY', '=', 0,
           (SELECT COUNT_IF(Severity NOT IN ('Critical','Important','Moderate','Low','Unknown'))
              FROM RAW.PATCHING_REPORT)

    -- 7. RANGES ---------------------------------------------------------------------------------
    UNION ALL SELECT 'RAW', 'VULNERABILITY_MAPPING', 'CVSS_OUT_OF_RANGE', '=', 0,
           (SELECT COUNT_IF(CVSSScore < 0 OR CVSSScore > 10) FROM RAW.VULNERABILITY_MAPPING)
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'NEGATIVE_DAYS_SINCE_PATCH', '=', 0,
           (SELECT COUNT_IF(DaysSincePatch < 0) FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'RAW', 'PATCH_HISTORY', 'DURATION_OUT_OF_RANGE', '=', 0,
           (SELECT COUNT_IF(DeploymentDurationMinutes <= 0 OR DeploymentDurationMinutes > 720) FROM RAW.PATCH_HISTORY)
    UNION ALL SELECT 'RAW', 'SERVER_INVENTORY', 'SPEC_OUT_OF_RANGE', '=', 0,
           (SELECT COUNT_IF(CPUCount <= 0 OR MemoryGB <= 0 OR DiskSpaceGB <= 0) FROM RAW.SERVER_INVENTORY)

    -- 8. BUSINESS-LOGIC CONSISTENCY ---------------------------------------------------------------
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'INSTALLED_NOT_COMPLIANT', '=', 0,
           (SELECT COUNT_IF(PatchStatus = 'Installed' AND ComplianceStatus <> 'Compliant') FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'INSTALLED_BEFORE_RELEASE', '=', 0,
           (SELECT COUNT_IF(PatchInstalledDate < PatchReleaseDate) FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'RAW', 'PATCHING_REPORT', 'INSTALLED_WITHOUT_INSTALL_DATE_PCT', '<=', 2,
           (SELECT ROUND(100 * COUNT_IF(PatchStatus = 'Installed' AND PatchInstalledDate IS NULL)
                         / NULLIF(COUNT_IF(PatchStatus = 'Installed'), 0), 4) FROM RAW.PATCHING_REPORT)
    UNION ALL SELECT 'CORE', 'FACT_PATCH_STATUS', 'STATUS_CONFLICT_PCT', '<=', 2,
           (SELECT ROUND(100 * SUM(has_status_conflict) / COUNT(*), 4) FROM CORE.FACT_PATCH_STATUS)
    UNION ALL SELECT 'CORE', 'FACT_PATCH_DEPLOYMENT', 'STATUS_CONFLICT_PCT', '<=', 2,
           (SELECT ROUND(100 * SUM(has_status_conflict) / COUNT(*), 4) FROM CORE.FACT_PATCH_DEPLOYMENT)
  )
  SELECT :P_RUN_ID, CURRENT_TIMESTAMP(), layer, tbl, chk, op, thr, actual,
         CASE WHEN op = '='  AND actual  = thr THEN 'PASS'
              WHEN op = '<=' AND actual <= thr THEN 'PASS'
              ELSE 'FAIL' END
  FROM checks;

  RETURN 'DO checks logged for run ' || P_RUN_ID;
END;
$$;

-- Run once by hand
CALL DO.SP_RUN_DO_CHECKS('manual_run_1');

-- (d) REPORT: latest run + overall pass rate ------------------------------------------------------
CREATE OR REPLACE VIEW DO.VW_DO_LATEST_RUN AS
SELECT * FROM DO.CHECK_RESULTS
WHERE RUN_ID = (SELECT RUN_ID FROM DO.CHECK_RESULTS ORDER BY RUN_TS DESC LIMIT 1);

SELECT COUNT(*) AS checks_run,
       COUNT_IF(STATUS = 'PASS') AS passed,
       COUNT_IF(STATUS = 'FAIL') AS failed,
       ROUND(100 * COUNT_IF(STATUS = 'PASS') / COUNT(*), 1) AS check_pass_rate_pct
FROM DO.VW_DO_LATEST_RUN;

SELECT LAYER, TABLE_NAME, CHECK_NAME, OPERATOR, THRESHOLD, ACTUAL, STATUS
FROM DO.VW_DO_LATEST_RUN
ORDER BY STATUS, LAYER, TABLE_NAME;      -- failures first: investigate every FAIL, do not ignore it