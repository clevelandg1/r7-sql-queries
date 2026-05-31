-- Operating System EOL Inventory
-- Inventory of OS families/versions with asset counts, flagging versions that
-- are likely End-of-Life based on common name patterns. Review and extend the
-- EOL pattern list to match the platforms in your environment.
-- Adapted/genericized from Rapid7 community obsolete-OS queries.

SELECT
    dos.name                                            AS os_family,
    dos.version                                         AS os_version,
    COUNT(DISTINCT daos.asset_id)                       AS asset_count,
    CASE
        WHEN dos.name ILIKE '%windows%' AND (
                 dos.name ILIKE '%2000%'  OR dos.name ILIKE '% xp%'
              OR dos.name ILIKE '%2003%'  OR dos.name ILIKE '%2008%'
              OR dos.name ILIKE '% 7%'    OR dos.name ILIKE '%vista%'
              OR dos.name ILIKE '%2012%') THEN 'Likely EOL'
        WHEN dos.name ILIKE '%cent%' OR dos.name ILIKE '%enterprise linux%5%'
              OR dos.name ILIKE '%ubuntu%14%' OR dos.name ILIKE '%ubuntu%16%' THEN 'Likely EOL'
        ELSE 'Review'
    END                                                 AS eol_flag
FROM dim_asset_operating_system daos
JOIN dim_operating_system dos ON dos.operating_system_id = daos.operating_system_id
JOIN dim_asset da             ON da.asset_id = daos.asset_id
GROUP BY dos.name, dos.version
ORDER BY asset_count DESC;
