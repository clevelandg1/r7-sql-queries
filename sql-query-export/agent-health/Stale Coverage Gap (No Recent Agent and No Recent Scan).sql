-- Stale Coverage Gap (No Recent Agent and No Recent Scan)
-- Blind-spot assets with no completed scan inside the staleness window AND no recent
-- agent assessment. dim_asset_unique_id carries no check-in timestamp, so
-- dim_asset.last_assessed_for_vulnerabilities is used as the agent recency proxy.
-- Edit stale_days below to change the window (default 30 days).

WITH params AS (
    SELECT 30 AS stale_days
),
-- Most recent completed scan per asset
last_scan AS (
    SELECT
        das.asset_id,
        MAX(ds.finished) AS last_scan_finished
    FROM dim_asset_scan das
    JOIN dim_scan ds ON ds.scan_id = das.scan_id
    WHERE ds.finished IS NOT NULL
    GROUP BY das.asset_id
),
-- Assets with an Insight Agent installed
agent_assets AS (
    SELECT DISTINCT asset_id
    FROM dim_asset_unique_id
    WHERE source = 'R7 Agent'
),
base AS (
    SELECT
        da.asset_id,
        da.ip_address,
        da.host_name,
        da.sites,
        da.operating_system_id,
        da.last_assessed_for_vulnerabilities,
        ls.last_scan_finished,
        (aa.asset_id IS NOT NULL) AS has_agent,
        p.stale_days,
        (NOW() - (p.stale_days || ' days')::interval) AS stale_cutoff
    FROM dim_asset da
    CROSS JOIN params p
    LEFT JOIN last_scan    ls ON ls.asset_id = da.asset_id
    LEFT JOIN agent_assets aa ON aa.asset_id = da.asset_id
)
SELECT
    b.asset_id,
    b.ip_address,
    b.host_name,
    b.sites,
    dos.description                                                   AS operating_system,
    b.has_agent,
    b.last_scan_finished,
    b.last_assessed_for_vulnerabilities,
    FLOOR(EXTRACT(EPOCH FROM (NOW() - b.last_scan_finished)) / 86400)::int
                                                                      AS days_since_last_scan,
    FLOOR(EXTRACT(EPOCH FROM (NOW() - b.last_assessed_for_vulnerabilities)) / 86400)::int
                                                                      AS days_since_last_assessment,
    CASE
        WHEN NOT b.has_agent AND b.last_scan_finished IS NULL THEN 'Never Scanned, No Agent'
        WHEN NOT b.has_agent                                  THEN 'No Agent, Scan Stale'
        WHEN b.last_scan_finished IS NULL                     THEN 'Agent Present, Never Scanned, Assessment Stale'
        ELSE 'Agent Present, Scan And Assessment Both Stale'
    END                                                               AS gap_reason
FROM base b
LEFT JOIN dim_operating_system dos ON dos.operating_system_id = b.operating_system_id
WHERE
    -- No completed scan inside the window
    (b.last_scan_finished IS NULL OR b.last_scan_finished < b.stale_cutoff)
    -- And no agent, or agent assessment is equally stale
    AND (
        NOT b.has_agent
        OR b.last_assessed_for_vulnerabilities IS NULL
        OR b.last_assessed_for_vulnerabilities < b.stale_cutoff
    )
ORDER BY days_since_last_scan DESC NULLS FIRST, b.asset_id;
