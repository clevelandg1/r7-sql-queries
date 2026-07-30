-- Asset Inventory With First and Last Discovered
-- Full asset inventory (IP, host, MAC, OS, sites) with first/last discovery dates.
-- First/last discovered come from fact_asset_discovery (accumulating snapshot);
-- site memberships are pre-rolled per asset so each asset returns exactly one row.

WITH site_rollup AS (
    -- Collapse an asset's (possibly multiple) site memberships to one row
    SELECT
        dsa.asset_id,
        COUNT(DISTINCT ds.site_id)               AS site_count,
        STRING_AGG(DISTINCT ds.importance, ', ') AS site_importance_levels
    FROM dim_site_asset dsa
    JOIN dim_site ds ON ds.site_id = dsa.site_id
    GROUP BY dsa.asset_id
)
SELECT
    da.asset_id,
    da.ip_address,
    da.host_name,
    da.mac_address,
    dos.vendor                            AS os_vendor,
    dos.family                            AS os_family,
    dos.name                              AS os_name,
    dos.version                           AS os_version,
    da.sites                              AS site_names,
    sr.site_count,
    sr.site_importance_levels,
    fad.first_discovered,
    fad.last_discovered,
    da.last_assessed_for_vulnerabilities  AS last_assessed
FROM dim_asset da
LEFT JOIN fact_asset_discovery fad   ON fad.asset_id = da.asset_id
LEFT JOIN dim_operating_system dos   ON dos.operating_system_id = da.operating_system_id
LEFT JOIN site_rollup sr             ON sr.asset_id = da.asset_id
ORDER BY fad.first_discovered NULLS LAST, da.host_name;
