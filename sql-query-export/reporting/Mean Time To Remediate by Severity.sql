-- Mean Time To Remediate by Severity
-- Average and median days from first discovery to remediation, grouped by severity.
-- Remediation is inferred as asset/vulnerability pairs seen in scan history but no
-- longer present in the current open finding set (fact_asset_vulnerability_finding).
-- To scope to a business unit, join dim_tag_asset / dim_tag on asset_id and filter
-- by your tag prefix (e.g. 'YOUR-TAG-PREFIX-%').

WITH last_seen AS (
    -- Most recent scan date in which each asset/vulnerability pair was observed
    SELECT
        fasvf.asset_id,
        fasvf.vulnerability_id,
        MAX(ds.finished)::date AS last_seen_date
    FROM fact_asset_scan_vulnerability_finding fasvf
    JOIN dim_scan ds ON ds.scan_id = fasvf.scan_id
    GROUP BY fasvf.asset_id, fasvf.vulnerability_id
),
remediated AS (
    -- Keep only pairs no longer in the current open finding set (anti-join),
    -- and compute days from first discovery to last time the finding was seen
    SELECT
        ls.asset_id,
        ls.vulnerability_id,
        (ls.last_seen_date - age.first_discovered::date) AS days_to_remediate
    FROM last_seen ls
    JOIN fact_asset_vulnerability_age age
      ON age.asset_id = ls.asset_id
     AND age.vulnerability_id = ls.vulnerability_id
    LEFT JOIN fact_asset_vulnerability_finding open_f
      ON open_f.asset_id = ls.asset_id
     AND open_f.vulnerability_id = ls.vulnerability_id
    WHERE open_f.asset_id IS NULL
      AND ls.last_seen_date >= age.first_discovered::date
)
SELECT
    dv.severity,
    COUNT(*)                                                                            AS vulnerabilities_remediated,
    ROUND(AVG(r.days_to_remediate)::numeric, 1)                                         AS avg_days_to_remediate,
    ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY r.days_to_remediate)::numeric, 1) AS median_days_to_remediate,
    MIN(r.days_to_remediate)                                                            AS min_days_to_remediate,
    MAX(r.days_to_remediate)                                                            AS max_days_to_remediate
FROM remediated r
JOIN dim_vulnerability dv ON dv.vulnerability_id = r.vulnerability_id
GROUP BY dv.severity
ORDER BY
    CASE dv.severity
        WHEN 'Critical' THEN 1
        WHEN 'Severe'   THEN 2
        WHEN 'Moderate' THEN 3
        ELSE 4
    END;
