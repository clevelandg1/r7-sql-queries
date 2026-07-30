-- Expiring Exceptions Watchlist
-- Approved vulnerability exceptions that expire within the next 90 days, bucketed
-- into 30/60/90-day windows (plus anything already expired but still flagged Approved),
-- with the exception scope target resolved to a site / asset / asset-group name.
-- Edit the 90 in the WHERE clause to widen or narrow the look-ahead window.

WITH expiring AS (
    -- Approved exceptions with a real expiration date inside the look-ahead window
    SELECT
        dve.vulnerability_exception_id,
        dve.vulnerability_id,
        dve.scope_id,
        dve.site_id,
        dve.asset_id,
        dve.group_id,
        dve.port,
        dve.submitted_by,
        dve.submitted_date,
        dve.reviewed_by,
        dve.review_date,
        dve.expiration_date,
        dve.reason_id,
        (dve.expiration_date - CURRENT_DATE) AS days_until_expiration
    FROM dim_vulnerability_exception dve
    WHERE dve.status_id = 'A'                                   -- Approved / actively applied
      AND dve.expiration_date IS NOT NULL
      AND dve.expiration_date <= CURRENT_DATE + 90
)
SELECT
    e.vulnerability_exception_id,
    dsc.short_description                        AS exception_scope,
    -- Resolve whichever scope target applies; global exceptions have no target
    COALESCE(ds.name, da.host_name, HOST(da.ip_address), dag.name, 'All Assets (Global)')
                                                 AS scope_target,
    e.port,
    der.description                              AS exception_reason,
    dv.title                                     AS vulnerability_title,
    dv.severity,
    ROUND(dv.riskscore::numeric, 0)              AS risk_score,
    e.submitted_by,
    e.submitted_date::date                       AS submitted_date,
    e.reviewed_by,
    e.review_date::date                          AS review_date,
    e.expiration_date,
    e.days_until_expiration,
    -- Triage bucket
    CASE
        WHEN e.days_until_expiration <  0  THEN 'Already Expired'
        WHEN e.days_until_expiration <= 30 THEN 'Expires 0-30 Days'
        WHEN e.days_until_expiration <= 60 THEN 'Expires 31-60 Days'
        ELSE                                    'Expires 61-90 Days'
    END                                          AS expiration_bucket
FROM expiring e
JOIN dim_vulnerability          dv  ON dv.vulnerability_id  = e.vulnerability_id
JOIN dim_exception_reason       der ON der.reason_id        = e.reason_id
JOIN dim_exception_scope        dsc ON dsc.scope_id         = e.scope_id
LEFT JOIN dim_site              ds  ON ds.site_id           = e.site_id
LEFT JOIN dim_asset             da  ON da.asset_id          = e.asset_id
LEFT JOIN dim_asset_group       dag ON dag.asset_group_id   = e.group_id
ORDER BY
    e.expiration_date,
    dv.severity_score DESC,
    dv.riskscore DESC;
