-- Mean Time To Remediate by Severity
-- Average and median days from first discovery to remediation, grouped by severity.
-- The InsightVM data model has no explicit remediation date, so remediation is
-- inferred from scan history: a finding observed across scans
-- (fact_asset_scan_vulnerability_finding) that is absent from the current open
-- finding set (fact_asset_vulnerability_finding) is treated as remediated, with
-- time-to-remediate measured from its first to its last observed scan.
-- To scope to a business unit, join dim_tag_asset / dim_tag and filter the tag name.

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
        (fh.last_seen - fh.first_seen) AS days_to_remediate
    FROM finding_history fh
    LEFT JOIN fact_asset_vulnerability_finding open_f
      ON open_f.asset_id        = fh.asset_id
     AND open_f.vulnerability_id = fh.vulnerability_id
    JOIN dim_vulnerability dv ON dv.vulnerability_id = fh.vulnerability_id
    WHERE open_f.asset_id IS NULL
)
SELECT
    severity,
    COUNT(*)                                                                            AS vulnerabilities_remediated,
    ROUND(AVG(days_to_remediate)::numeric, 1)                                           AS avg_days_to_remediate,
    ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY days_to_remediate)::numeric, 1)   AS median_days_to_remediate,
    MIN(days_to_remediate)                                                              AS min_days_to_remediate,
    MAX(days_to_remediate)                                                              AS max_days_to_remediate
FROM remediated
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'Severe'   THEN 2
        WHEN 'Moderate' THEN 3
        ELSE 4
    END;
