-- Duplicate Assets Report
-- Identifies assets that share the same hostname, which may indicate
-- duplicate entries or misconfigured assets in the environment

SELECT
    host_name,
    ARRAY_AGG(asset_id) AS asset_ids,
    COUNT(asset_id) AS number_of_assets
FROM
    dim_asset
GROUP BY
    host_name
HAVING
    COUNT(asset_id) > 1;