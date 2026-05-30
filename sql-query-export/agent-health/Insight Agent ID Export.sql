-- Insight Agent ID Export
-- Exports the Rapid7 Insight Agent unique ID for every asset reporting an agent,
-- alongside asset_id and IP (source = 'R7 Agent').

SELECT
    da.asset_id,
    da.ip_address,
    daui.source,
    daui.unique_id
FROM dim_asset da
JOIN dim_asset_unique_id daui USING (asset_id)
WHERE source = 'R7 Agent';
