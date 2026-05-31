-- Vulnerabilities Remediated Within SLA
-- Counts vulnerability findings that were remediated inside vs. outside a
-- 30-day remediation SLA, based on how long each finding was open.
-- Adjust the SLA threshold (30) to match your organization's policy.
-- NOTE: The InsightVM Reporting Data Model does not expose an explicit
-- remediation date, so "remediated" is inferred from fact_asset_vulnerability_age
-- where most_recently_discovered is older than the most recent scan finish
-- (the finding was not seen on the latest scan). Verify this assumption fits
-- your data retention / scan cadence.

WITH last_scan AS (
    -- Most recent scan finish time per asset, used as the "remediated by" boundary
    SELECT asset_id, MAX(scan_finished) AS last_scan_finished
    FROM dim_asset_scan
    GROUP BY asset_id
),
remediated AS (
    -- A finding is treated as remediated when it was not seen on the latest scan
    SELECT
        dv.severity,
        (age.most_recently_discovered::date - age.first_discovered::date) AS days_open
    FROM fact_asset_vulnerability_age age
    JOIN last_scan ls ON ls.asset_id = age.asset_id
    JOIN dim_vulnerability dv ON dv.vulnerability_id = age.vulnerability_id
    WHERE age.most_recently_discovered < ls.last_scan_finished
)
SELECT
    severity,
    COUNT(*)                                              AS remediated_count,
    COUNT(*) FILTER (WHERE days_open <= 30)               AS within_sla,
    COUNT(*) FILTER (WHERE days_open >  30)               AS outside_sla,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE days_open <= 30)
        / NULLIF(COUNT(*), 0)
    , 0)                                                  AS pct_within_sla
FROM remediated
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'Severe'   THEN 2
        WHEN 'Moderate' THEN 3
        ELSE 4
    END;
