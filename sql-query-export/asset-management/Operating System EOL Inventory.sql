-- Operating System EOL / Obsolete Inventory
-- Lists assets running an obsolete / end-of-life operating system using Rapid7's
-- own "Obsolete" vulnerability category (dim_vulnerability_category) instead of
-- hard-coded OS version patterns, so results stay accurate as content updates.
-- Obsolete-OS detections are vulnerability findings; this counts current open
-- findings whose check is categorized Obsolete and whose title names an OS.
-- Drop the dv.title filter to include obsolete software as well as operating systems.

WITH obsolete_os_vulns AS (
    -- Vulnerability checks Rapid7 classifies as Obsolete that pertain to an OS
    SELECT DISTINCT dv.vulnerability_id
    FROM dim_vulnerability_category vc
    JOIN dim_vulnerability dv ON dv.vulnerability_id = vc.vulnerability_id
    WHERE vc.category_name ILIKE '%obsolete%'
      AND dv.title         ILIKE '%operating system%'   -- remove to include all obsolete software
),
obsolete_findings AS (
    -- Current open findings for those checks (one row per asset/check)
    SELECT DISTINCT favf.asset_id
    FROM fact_asset_vulnerability_finding favf
    JOIN obsolete_os_vulns oov ON oov.vulnerability_id = favf.vulnerability_id
)
SELECT
    dos.vendor,
    dos.family,
    dos.name                       AS os_name,
    dos.version                    AS os_version,
    COUNT(DISTINCT obf.asset_id)   AS obsolete_asset_count
FROM obsolete_findings obf
JOIN dim_asset da             ON da.asset_id = obf.asset_id
JOIN dim_operating_system dos ON dos.operating_system_id = da.operating_system_id
GROUP BY dos.vendor, dos.family, dos.name, dos.version
ORDER BY obsolete_asset_count DESC, dos.vendor, dos.name;
