-- Credential Coverage Scorecard by Site
-- Per-site scorecard of authenticated vs. unauthenticated assets and the
-- percentage successfully authenticated. Successful = aggregated credential
-- status of 'All credentials successful' or 'Credentials partially successful'.
-- Adapted and genericized from Rapid7 community credential-status queries.

WITH asset_auth AS (
    SELECT
        fa.asset_id,
        CASE
            WHEN dacs.aggregated_credential_status_description
                 IN ('All credentials successful', 'Credentials partially successful')
            THEN 1 ELSE 0
        END AS is_authenticated
    FROM fact_asset fa
    JOIN dim_aggregated_credential_status dacs
        ON dacs.aggregated_credential_status_id = fa.aggregated_credential_status_id
)
SELECT
    dsite.name                                          AS site_name,
    COUNT(DISTINCT dsa.asset_id)                        AS total_assets,
    SUM(aa.is_authenticated)                            AS authenticated_assets,
    COUNT(DISTINCT dsa.asset_id) - SUM(aa.is_authenticated)
                                                        AS unauthenticated_assets,
    ROUND(
        100.0 * SUM(aa.is_authenticated)
        / NULLIF(COUNT(DISTINCT dsa.asset_id), 0)
    , 0)                                                AS pct_authenticated
FROM dim_site_asset dsa
JOIN dim_site dsite ON dsite.site_id = dsa.site_id
JOIN asset_auth aa  ON aa.asset_id = dsa.asset_id
GROUP BY dsite.name
ORDER BY pct_authenticated ASC, total_assets DESC;
