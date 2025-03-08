SELECT 
    a.ip_address,
    a.host_name,
    a.operating_system_id,
    os.description AS operating_system,
    COUNT(f.vulnerability_id) AS critical_vulnerability_count
FROM dim_asset a
JOIN fact_asset_vulnerability_finding f ON a.asset_id = f.asset_id
JOIN dim_vulnerability v ON f.vulnerability_id = v.vulnerability_id
JOIN dim_operating_system os ON a.operating_system_id = os.operating_system_id
WHERE v.severity = 'Critical'
GROUP BY a.ip_address, a.host_name, a.operating_system_id, os.description
ORDER BY critical_vulnerability_count DESC
LIMIT 10;