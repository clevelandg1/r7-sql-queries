-- Unauthenticated Assets
-- Lists assets whose aggregated credential status is NOT successful, so scans
-- could not fully authenticate. Adapted/genericized from Rapid7 community
-- "Unauthenticated Assets" queries.

SELECT
    dsite.name                                          AS site_name,
    da.ip_address,
    da.host_name,
    dacs.aggregated_credential_status_description       AS credential_status
FROM fact_asset fa
JOIN dim_asset da   ON da.asset_id = fa.asset_id
JOIN dim_aggregated_credential_status dacs
    ON dacs.aggregated_credential_status_id = fa.aggregated_credential_status_id
LEFT JOIN dim_site_asset dsa ON dsa.asset_id = fa.asset_id
LEFT JOIN dim_site dsite     ON dsite.site_id = dsa.site_id
WHERE dacs.aggregated_credential_status_description
      NOT IN ('All credentials successful', 'Credentials partially successful')
ORDER BY dsite.name, HOST(da.ip_address);
