-- Scan Failure and Duration Trend
-- Monthly scan outcomes (successful / failed / aborted / stopped) and scan duration stats,
-- broken out by site and scan engine, to surface flaky engines and long-running scans.
-- Engine reflects each site's currently-configured engine; edit the date window in the WHERE clause.

WITH scans AS (
    SELECT
        ds.scan_id,
        date_trunc('month', ds.started)::date         AS scan_month,
        dsite.name                                     AS site_name,
        eng.name                                       AS scan_engine,
        sstat.description                              AS scan_status,
        stype.description                              AS scan_type,
        CASE
            WHEN ds.finished IS NOT NULL
            THEN EXTRACT(EPOCH FROM (ds.finished - ds.started)) / 60.0
        END                                            AS duration_minutes
    FROM dim_scan ds
    JOIN dim_site_scan dss        ON dss.scan_id = ds.scan_id
    JOIN dim_site dsite           ON dsite.site_id = dss.site_id
    JOIN dim_scan_status sstat    ON sstat.status_id = ds.status_id
    JOIN dim_scan_type stype      ON stype.type_id = ds.type_id
    LEFT JOIN dim_site_scan_config cfg ON cfg.site_id = dss.site_id
    LEFT JOIN dim_scan_engine eng      ON eng.scan_engine_id = cfg.scan_engine_id
    -- Edit window: last 12 months by default
    WHERE ds.started >= date_trunc('month', CURRENT_DATE) - INTERVAL '12 months'
)
SELECT
    scan_month,
    site_name,
    COALESCE(scan_engine, 'Unknown / Unassigned')                              AS scan_engine,
    COUNT(*)                                                                    AS total_scans,
    COUNT(*) FILTER (WHERE scan_status = 'Successful')                          AS successful_scans,
    COUNT(*) FILTER (WHERE scan_status = 'Failed')                             AS failed_scans,
    COUNT(*) FILTER (WHERE scan_status = 'Aborted')                            AS aborted_scans,
    COUNT(*) FILTER (WHERE scan_status = 'Stopped')                            AS stopped_scans,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE scan_status IN ('Failed', 'Aborted', 'Stopped'))
        / NULLIF(COUNT(*), 0)
    , 1)                                                                        AS failure_rate_pct,
    ROUND(AVG(duration_minutes)::numeric, 1)                                    AS avg_duration_min,
    ROUND(
        (percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_minutes))::numeric
    , 1)                                                                        AS median_duration_min,
    ROUND(MAX(duration_minutes)::numeric, 1)                                    AS max_duration_min
FROM scans
GROUP BY scan_month, site_name, scan_engine
ORDER BY scan_month DESC, failure_rate_pct DESC, total_scans DESC, site_name;
