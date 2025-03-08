-- This query finds vulnerabilities that were present in a previous scan
-- but are no longer present in the most recent scan for assets in scope
-- Limited to remediation confirmed within the last 7 days
SELECT 
    a.ip_address,
    a.host_name,
    v.title AS vulnerability_title,
    v.severity_score,
    v.description,
    to_char(prev_scan.scan_finished, 'YYYY-MM-DD HH24:MI:SS') AS first_detected,
    to_char(prev_scan.scan_finished, 'YYYY-MM-DD HH24:MI:SS') AS last_seen,
    to_char(last_scan.scan_finished, 'YYYY-MM-DD HH24:MI:SS') AS remediation_confirmed_date
FROM dim_asset a
JOIN dim_asset_scan last_scan ON a.asset_id = last_scan.asset_id AND last_scan.scan_id = lastScan(a.asset_id)
JOIN dim_asset_scan prev_scan ON a.asset_id = prev_scan.asset_id AND prev_scan.scan_id = previousScan(a.asset_id)
JOIN fact_asset_scan_vulnerability_finding prev_finding ON prev_scan.scan_id = prev_finding.scan_id AND a.asset_id = prev_finding.asset_id
JOIN dim_vulnerability v ON prev_finding.vulnerability_id = v.vulnerability_id
-- Filter for vulnerabilities not in the most recent scan
WHERE NOT EXISTS (
    SELECT 1 
    FROM fact_asset_scan_vulnerability_finding current_finding
    WHERE current_finding.scan_id = last_scan.scan_id
    AND current_finding.asset_id = a.asset_id
    AND current_finding.vulnerability_id = prev_finding.vulnerability_id
)
-- Add filter for scans within the last 7 days
AND last_scan.scan_finished >= (CURRENT_DATE - INTERVAL '7 days')
ORDER BY a.host_name, v.severity_score DESC;