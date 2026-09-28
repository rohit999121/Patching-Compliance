USE WAREHOUSE SCCM_WH; USE DATABASE SCCM_DB;

CREATE OR REPLACE PROCEDURE ETL.SP_BUILD_CORE()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN


  CREATE OR REPLACE TABLE CORE.DIM_DATE AS
  WITH days AS (
    SELECT DATEADD('day', ROW_NUMBER() OVER (ORDER BY SEQ4()) - 1, '2022-01-01'::DATE) AS full_date
    FROM TABLE(GENERATOR(ROWCOUNT => 2922))                       -- 2022-01-01 .. 2029-12-31
  )
  SELECT TO_NUMBER(TO_CHAR(full_date, 'YYYYMMDD'))  AS date_key,
         full_date,
         YEAR(full_date) AS cal_year,
         QUARTER(full_date) AS cal_quarter,
         MONTH(full_date) AS month_num,
         MONTHNAME(full_date) AS month_name,
         TO_CHAR(full_date, 'YYYY-MM') AS year_month,
         WEEKOFYEAR(full_date) AS week_of_year,
         DAYNAME(full_date) AS day_name,
         IFF(DAYOFWEEKISO(full_date) >= 6, TRUE, FALSE) AS is_weekend
  FROM days;


  CREATE OR REPLACE TABLE CORE.DIM_SERVER AS
  SELECT ROW_NUMBER() OVER (ORDER BY ServerID) AS server_key,     
         ServerID, ServerName, FQDN, IPAddress, Environment, BusinessUnit, ApplicationName,
         ApplicationOwner, ServerOwner, SupportTeam, Location, DataCenter, OperatingSystem, OSVersion,
         CPUCount, MemoryGB, DiskSpaceGB, ServerCriticality, ServerType, VirtualizationPlatform,
         BuildDate, CurrentStatus, CreatedDate, LastModifiedDate
  FROM RAW.SERVER_INVENTORY;

  INSERT INTO CORE.DIM_SERVER (server_key, ServerID, ServerName, Environment, BusinessUnit, Location,
                               OperatingSystem, ServerCriticality, CurrentStatus)
  VALUES (-1, 'UNKNOWN', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown');

  ---------------------------------------------------------------------------------------------
  -- DIM_KB: one row per KB article = patch attributes + vulnerability exposure summary.
  -- NULLIF(...,'Unknown') stops the placeholder text from winning MAX() over the real value.
  ---------------------------------------------------------------------------------------------
  CREATE OR REPLACE TABLE CORE.DIM_KB AS
  WITH all_kb AS (
    SELECT KBNumber FROM RAW.PATCHING_REPORT
    UNION SELECT KBNumber FROM RAW.PATCH_HISTORY
    UNION SELECT KBNumber FROM RAW.VULNERABILITY_MAPPING
  ),
  patch_attr AS (
    SELECT KBNumber,
           MAX(NULLIF(PatchTitle, 'Unknown')) AS PatchTitle,
           MAX(NULLIF(PatchCategory, 'Unknown')) AS PatchCategory,
           MAX(NULLIF(Severity, 'Unknown')) AS Severity,
           MAX(PatchReleaseDate) AS PatchReleaseDate
    FROM RAW.PATCHING_REPORT
    GROUP BY KBNumber
  ),
  vuln_attr AS (
    SELECT KBNumber,
           COUNT(DISTINCT CVEID) AS cve_count,
           MAX(CVSSScore) AS max_cvss,
           MAX(IFF(ExploitAvailable = 'Yes', 1, 0)) = 1   AS has_known_exploit
    FROM RAW.VULNERABILITY_MAPPING
    GROUP BY KBNumber
  )
  SELECT ROW_NUMBER() OVER (ORDER BY a.KBNumber) AS kb_key,
         a.KBNumber,
         COALESCE(p.PatchTitle, 'Unknown') AS PatchTitle,
         COALESCE(p.PatchCategory, 'Unknown') AS PatchCategory,
         COALESCE(p.Severity, 'Unknown') AS Severity,
         p.PatchReleaseDate,
         COALESCE(v.cve_count, 0) AS cve_count,
         v.max_cvss,
         COALESCE(v.has_known_exploit, FALSE)      AS has_known_exploit
  FROM all_kb a
  LEFT JOIN patch_attr p ON p.KBNumber = a.KBNumber
  LEFT JOIN vuln_attr  v ON v.KBNumber = a.KBNumber;


  CREATE OR REPLACE TABLE CORE.DIM_CVE AS
  SELECT ROW_NUMBER() OVER (ORDER BY KBNumber, CVEID) AS cve_key,
         KBNumber, CVEID, CVSSScore, RiskRating, ExploitAvailable, Vendor, VulnerabilityCategory,
         PublishedDate, UpdatedDate, DQ_Flags
  FROM RAW.VULNERABILITY_MAPPING;

  
  CREATE OR REPLACE TABLE CORE.FACT_PATCH_STATUS AS
  SELECT p.RecordID,
         COALESCE(s.server_key, -1) AS server_key,
         p.ServerID,
         k.kb_key,
         p.KBNumber,
         TO_NUMBER(TO_CHAR(p.PatchReleaseDate, 'YYYYMMDD')) AS release_date_key,
         p.PatchStatus, p.ComplianceStatus, p.DeploymentStatus, p.DeploymentName, p.PatchSource,
         p.RebootRequired,
         p.PatchReleaseDate, p.PatchInstalledDate, p.LastScanDate, p.DeploymentDeadline,
         p.DaysSincePatch, p.DaysToInstall,
         IFF(p.ComplianceStatus IN ('Compliant', 'Non-Compliant'), 1, 0)  AS is_applicable,
         IFF(p.ComplianceStatus = 'Compliant', 1, 0) AS is_compliant,
         IFF(p.PatchStatus = 'Installed', 1, 0) AS is_installed,
         IFF(p.PatchStatus = 'Installed' AND p.PatchInstalledDate <= p.DeploymentDeadline, 1, 0) AS installed_on_time,
         IFF(p.PatchStatus IN ('Missing', 'Failed', 'Pending')
             AND p.DeploymentDeadline < p.LastScanDate, 1, 0) AS is_overdue,
         IFF(CONTAINS(p.DQ_Flags, 'STATUS_CONFLICT'), 1, 0) AS has_status_conflict,
         IFF(CONTAINS(p.DQ_Flags, 'ORPHAN_SERVER'), 1, 0) AS is_orphan_server,
         p.DQ_Flags
  FROM RAW.PATCHING_REPORT p
  LEFT JOIN CORE.DIM_SERVER s ON s.ServerID = p.ServerID
  LEFT JOIN CORE.DIM_KB     k ON k.KBNumber = p.KBNumber;

  
  CREATE OR REPLACE TABLE CORE.FACT_PATCH_DEPLOYMENT AS
  SELECT h.HistoryID,
         COALESCE(s.server_key, -1) AS server_key,
         h.ServerID,
         k.kb_key,
         h.KBNumber,
         DATE_FROM_PARTS(h.PatchYear, h.PatchMonth, 1) AS period_start_date,
         h.PatchYear, h.PatchMonth, h.DeploymentCycle, h.PatchStatus, h.DeploymentStatus,
         h.PatchInstalledDate, h.DeploymentDurationMinutes, h.RebootRequired,
         h.PatchFailureReason, h.DaysToCompliance,
         IFF(h.PatchStatus IN ('Installed', 'Failed', 'Rolled Back'), 1, 0) AS is_attempted,
         IFF(h.PatchStatus = 'Installed', 1, 0) AS is_success,
         IFF(h.PatchStatus IN ('Failed', 'Rolled Back'), 1, 0) AS is_failure,
         IFF(CONTAINS(h.DQ_Flags, 'STATUS_CONFLICT'), 1, 0) AS has_status_conflict,
         IFF(CONTAINS(h.DQ_Flags, 'ORPHAN_SERVER'), 1, 0) AS is_orphan_server,
         h.DQ_Flags
  FROM RAW.PATCH_HISTORY h
  LEFT JOIN CORE.DIM_SERVER s ON s.ServerID = h.ServerID
  LEFT JOIN CORE.DIM_KB     k ON k.KBNumber = h.KBNumber;

  RETURN 'CORE build complete';
END;
$$;

CALL ETL.SP_BUILD_CORE();


SELECT 'DIM_SERVER' AS tbl, COUNT(*) AS row_count FROM CORE.DIM_SERVER            -- 97,000 + 1 unknown
UNION ALL SELECT 'DIM_KB', COUNT(*) FROM CORE.DIM_KB
UNION ALL SELECT 'DIM_CVE', COUNT(*) FROM CORE.DIM_CVE                          -- 95,737
UNION ALL SELECT 'FACT_PATCH_STATUS', COUNT(*) FROM CORE.FACT_PATCH_STATUS                -- 96,990
UNION ALL SELECT 'FACT_PATCH_DEPLOYMENT',COUNT(*) FROM CORE.FACT_PATCH_DEPLOYMENT;  

SELECT s.Environment, k.Severity, COUNT(*) AS records
FROM CORE.FACT_PATCH_STATUS f
JOIN CORE.DIM_SERVER s ON s.server_key = f.server_key
JOIN CORE.DIM_KB     k ON k.kb_key     = f.kb_key
GROUP BY 1, 2 ORDER BY 1, 2;

SELECT * FROM CORE.DIM_DATE
SELECT * FROM CORE.DIM_SERVER