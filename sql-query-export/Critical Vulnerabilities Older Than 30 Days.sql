SELECT 
    a.ip_address,
    a.host_name,
    v.title AS vulnerability,
    v.severity_score,
    to_char(age.first_discovered, 'YYYY-MM-DD') AS first_discovered,
    EXTRACT(DAY FROM (CURRENT_TIMESTAMP - age.first_discovered)) AS days_old
FROM fact_asset_vulnerability_age age
JOIN dim_asset a ON age.asset_id = a.asset_id
JOIN dim_vulnerability v ON age.vulnerability_id = v.vulnerability_id
WHERE v.severity = 'Critical'
AND age.first_discovered < (CURRENT_DATE - INTERVAL '30 days')
ORDER BY days_old DESC;