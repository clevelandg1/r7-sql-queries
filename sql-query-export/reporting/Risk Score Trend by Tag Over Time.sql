-- Risk Score Trend by Tag Over Time
-- Aggregated risk-score time series: total, average, and peak asset risk per tag per interval.
-- Tag-level roll-up companion to the per-asset "Historical Vulnerability Trend by Tag".
-- Edit the two date literals, the INTERVAL, and the tag prefix/type before running.

SELECT
    dt.tag_name,
    dt.tag_type,
    fad.day                                   AS snapshot_date,
    TO_CHAR(fad.day, 'Mon YYYY')              AS period_label,
    COUNT(DISTINCT fad.asset_id)              AS assets,
    ROUND(SUM(fad.riskscore)::NUMERIC)        AS total_risk_score,
    ROUND(AVG(fad.riskscore)::NUMERIC)        AS avg_asset_risk_score,
    ROUND(MAX(fad.riskscore)::NUMERIC)        AS max_asset_risk_score,
    SUM(fad.critical_vulnerabilities)         AS critical_vulnerabilities,
    SUM(fad.severe_vulnerabilities)           AS severe_vulnerabilities,
    SUM(fad.vulnerabilities)                  AS total_vulnerabilities,
    SUM(fad.vulnerabilities_with_exploit)     AS vulns_with_exploit
FROM fact_asset_date(
    '2026-01-01',
    '2026-07-01',
    INTERVAL '1 month'
) fad
JOIN dim_tag_asset dta USING (asset_id)
JOIN dim_tag dt        USING (tag_id)
-- Scope to your tag family; drop the tag_type filter to include all types.
WHERE dt.tag_name ILIKE 'YOUR-TAG-PREFIX-%'
  AND dt.tag_type IN ('CUSTOM', 'LOCATION', 'OWNER', 'CRITICALITY')
GROUP BY
    dt.tag_name,
    dt.tag_type,
    fad.day
ORDER BY
    dt.tag_name,
    fad.day;
