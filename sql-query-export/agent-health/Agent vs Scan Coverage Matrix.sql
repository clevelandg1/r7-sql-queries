-- Agent vs Scan Coverage Matrix
-- Classifies every asset by how it is covered: Insight Agent only, traditional
-- scan only, both, or neither. Agent presence is detected via dim_asset_unique_id
-- (source = 'R7 Agent'); scan coverage via the presence of any completed scan.

WITH agent_assets AS (
    SELECT DISTINCT asset_id
    FROM dim_asset_unique_id
    WHERE source = 'R7 Agent'
),
scanned_assets AS (
    SELECT DISTINCT asset_id
    FROM dim_asset_scan
),
classified AS (
    SELECT
        fa.asset_id,
        (aa.asset_id IS NOT NULL) AS has_agent,
        (sa.asset_id IS NOT NULL) AS has_scan
    FROM fact_asset fa
    LEFT JOIN agent_assets   aa ON aa.asset_id = fa.asset_id
    LEFT JOIN scanned_assets sa ON sa.asset_id = fa.asset_id
)
SELECT
    CASE
        WHEN has_agent AND has_scan THEN 'Both (Agent + Scan)'
        WHEN has_agent              THEN 'Agent Only'
        WHEN has_scan               THEN 'Scan Only'
        ELSE 'Neither'
    END                                                 AS coverage_type,
    COUNT(*)                                             AS asset_count,
    ROUND(100.0 * COUNT(*) / NULLIF(SUM(COUNT(*)) OVER (), 0), 0)
                                                        AS pct_of_assets
FROM classified
GROUP BY 1
ORDER BY asset_count DESC;
