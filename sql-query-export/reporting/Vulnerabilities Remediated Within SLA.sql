-- Vulnerabilities Remediated Within SLA
-- Counts vulnerability findings remediated inside vs. outside a 30-day SLA.
-- The InsightVM data model exposes no explicit remediation date, so a finding is
-- treated as remediated when it appears in an asset's scan history
-- (fact_asset_scan_vulnerability_finding) but is absent from the current open
-- finding set (fact_asset_vulnerability_finding). Days-open is measured from the
-- first to the last scan in which the finding was observed. Adjust the 30-day SLA.

WITH finding_history AS (
    -- First and last scan-finish dates each asset/vuln was observed in history
    SELECT
        fasvf.asset_id,
        fasvf.vulnerability_id,
        MIN(ds.finished)::date AS first_seen,
        MAX(ds.finished)::date AS last_seen
    FROM fact_asset_scan_vulnerability_finding fasvf
    JOIN dim_scan ds ON ds.scan_id = fasvf.scan_id
    GROUP BY fasvf.asset_id, fasvf.vulnerability_id
),
remediated AS (
    -- Keep only asset/vuln pairs no longer present in the current open finding set
    SELECT
        dv.severity,
        (fh.last_seen - fh.first_seen) AS days_open
    FROM finding_history fh
    LEFT JOIN fact_asset_vulnerability_finding open_f
      ON open_f.asset_id        = fh.asset_id
     AND open_f.vulnerability_id = fh.vulnerability_id
    JOIN dim_vulnerability dv ON dv.vulnerability_id = fh.vulnerability_id
    WHERE open_f.asset_id IS NULL
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
