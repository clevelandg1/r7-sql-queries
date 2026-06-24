-- Scan Coverage vs Configured Targets
-- Compares each site's configured included targets (dim_site_target) against the assets
-- that actually exist for that site (dim_site_asset -> dim_asset) to surface configured
-- targets with no matching live/scanned asset (coverage blind spots).
-- Single host and single-IP targets are matched directly; IP ranges/CIDR are flagged
-- for manual review since they cannot be matched one-to-one to a single asset.

WITH included_targets AS (
    -- Only included (not excluded) targets configured on each site
    SELECT
        st.site_id,
        st.type                                   AS target_type,   -- 'host' or 'ip'
        st.target                                 AS target_value,
        -- An IP target is a range/CIDR (not a single host) when it contains '-' or '/'
        (st.type = 'ip' AND (st.target LIKE '%-%' OR st.target LIKE '%/%')) AS is_range
    FROM dim_site_target st
    WHERE st.included = TRUE
),
site_assets AS (
    -- Live assets currently associated with each site
    SELECT
        sa.site_id,
        LOWER(da.host_name) AS host_name_lc,
        HOST(da.ip_address) AS ip_text
    FROM dim_site_asset sa
    JOIN dim_asset da ON da.asset_id = sa.asset_id
),
matched AS (
    -- Anti-join style: count how many live assets satisfy each single (non-range) target
    SELECT
        it.site_id,
        it.target_type,
        it.target_value,
        it.is_range,
        COUNT(sa.host_name_lc) AS matching_assets
    FROM included_targets it
    LEFT JOIN site_assets sa
        ON sa.site_id = it.site_id
       AND it.is_range = FALSE
       AND (
            (it.target_type = 'host' AND sa.host_name_lc = LOWER(it.target_value))
         OR (it.target_type = 'ip'   AND sa.ip_text      = it.target_value)
       )
    GROUP BY it.site_id, it.target_type, it.target_value, it.is_range
)
SELECT
    ds.name                AS site_name,
    m.target_type,
    m.target_value,
    CASE
        WHEN m.is_range            THEN 'IP range / CIDR - manual review'
        WHEN m.matching_assets > 0 THEN 'Covered'
        ELSE 'No live asset - coverage gap'
    END                    AS coverage_status
FROM matched m
JOIN dim_site ds ON ds.site_id = m.site_id
-- Show only the actionable rows: gaps and ranges that need a manual check
WHERE m.is_range = TRUE
   OR m.matching_assets = 0
ORDER BY ds.name, m.target_type, m.target_value;
