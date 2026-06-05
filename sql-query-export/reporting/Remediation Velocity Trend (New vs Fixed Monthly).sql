-- Remediation Velocity Trend (New vs Fixed Monthly)
-- Monthly gross new vulnerability findings vs. remediations over the trailing 12 months.
-- "New" = first time an (asset, vulnerability) pair appeared in scan history that month.
-- "Fixed" = last time a pair was seen that month and it is no longer in current open findings.
-- Net change = new minus fixed; a negative value indicates net improvement.
-- Adjust the lookback interval (currently 11 months back) as needed.

WITH scan_history AS (
    -- First and last scan-finish date for each asset/vulnerability pair across all scan history
    SELECT
        fasvf.asset_id,
        fasvf.vulnerability_id,
        MIN(ds.finished)::date AS first_seen,
        MAX(ds.finished)::date AS last_seen
    FROM fact_asset_scan_vulnerability_finding fasvf
    JOIN dim_scan ds ON ds.scan_id = fasvf.scan_id
    GROUP BY fasvf.asset_id, fasvf.vulnerability_id
),
classified AS (
    -- Tag each pair with its first-seen month; if remediated, also capture the fixed month
    SELECT
        sh.first_seen,
        sh.last_seen,
        DATE_TRUNC('month', sh.first_seen)::date AS first_month,
        CASE
            WHEN cur.asset_id IS NULL
                THEN DATE_TRUNC('month', sh.last_seen)::date
            ELSE NULL
        END AS fixed_month
    FROM scan_history sh
    LEFT JOIN fact_asset_vulnerability_finding cur
        ON cur.asset_id         = sh.asset_id
       AND cur.vulnerability_id  = sh.vulnerability_id
),
months AS (
    -- Trailing 12 calendar months including the current partial month
    SELECT generate_series(
        DATE_TRUNC('month', CURRENT_DATE - INTERVAL '11 months'),
        DATE_TRUNC('month', CURRENT_DATE),
        INTERVAL '1 month'
    )::date AS month
),
new_by_month AS (
    SELECT
        first_month        AS month,
        COUNT(*)           AS new_findings
    FROM classified
    WHERE first_month >= (SELECT MIN(month) FROM months)
    GROUP BY first_month
),
fixed_by_month AS (
    SELECT
        fixed_month        AS month,
        COUNT(*)           AS fixed_findings
    FROM classified
    WHERE fixed_month IS NOT NULL
      AND fixed_month >= (SELECT MIN(month) FROM months)
    GROUP BY fixed_month
)
SELECT
    m.month                                                               AS month_start,
    TO_CHAR(m.month, 'Mon YYYY')                                          AS month_label,
    COALESCE(n.new_findings,   0)                                         AS new_findings,
    COALESCE(f.fixed_findings, 0)                                         AS fixed_findings,
    COALESCE(n.new_findings, 0) - COALESCE(f.fixed_findings, 0)           AS net_change
FROM months m
LEFT JOIN new_by_month  n USING (month)
LEFT JOIN fixed_by_month f USING (month)
ORDER BY m.month;
