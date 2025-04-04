-- This query finds vulnerabilities that were present in a previous scan
-- but are no longer present in the most recent scan for assets in scope
-- Limited to remediation confirmed within the last 7 days
-- Vulnerability Remediation Progress Tracking Query

-- FILTERING OPTIONS:
-- 1. Specific Date Range
-- Replace: AND last_scan.scan_finished >= (CURRENT_DATE - INTERVAL '7 days')
-- With: AND last_scan.scan_finished BETWEEN '2023-01-01' AND '2023-01-31'

-- 2. Different Number of Days
-- Replace: AND last_scan.scan_finished >= (CURRENT_DATE - INTERVAL '7 days')
-- With: AND last_scan.scan_finished >= (CURRENT_DATE - INTERVAL '30 days')

-- 3. Specific Month
-- Replace: AND last_scan.scan_finished >= (CURRENT_DATE - INTERVAL '7 days')
-- With: AND to_char(last_scan.scan_finished, 'YYYY-MM') = '2023-01'

-- 4. Remove Date Filtering
-- Comment out or remove: 
-- AND last_scan.scan_finished >= (CURRENT_DATE - INTERVAL '7 days')

SELECT 
    a.ip_address, 
    a.host_name, 
    v.title AS vulnerability_title, 
    v.severity_score, 
    v.description, 
    prev_finding.vulnerability_instances AS previous_instances_count, 
    COALESCE(curr_finding.vulnerability_instances, 0) AS current_instances_count, 
    to_char(prev_scan.scan_finished, 'YYYY-MM-DD HH24:MI:SS') AS previous_scan_date, 
    to_char(last_scan.scan_finished, 'YYYY-MM-DD HH24:MI:SS') AS current_scan_date, 
    (prev_finding.vulnerability_instances - COALESCE(curr_finding.vulnerability_instances, 0)) AS instances_difference, 
    CASE 
        WHEN prev_finding.vulnerability_instances = 0 THEN '0%' 
        ELSE ROUND((prev_finding.vulnerability_instances - COALESCE(curr_finding.vulnerability_instances, 0))::numeric * 100 / prev_finding.vulnerability_instances::numeric, 2) || '%' 
    END AS percentage_reduction, 
    CASE 
        WHEN curr_finding.vulnerability_instances IS NULL THEN 'Fully Remediated' 
        ELSE 'Partially Remediated' 
    END AS remediation_status,
    -- Optional: Add solution information if available
    s.summary AS recommended_solution
FROM dim_asset a 
JOIN dim_asset_scan last_scan ON a.asset_id = last_scan.asset_id 
    AND last_scan.scan_id = lastScan(a.asset_id)
JOIN dim_asset_scan prev_scan ON a.asset_id = prev_scan.asset_id 
    AND prev_scan.scan_id = previousScan(a.asset_id)
JOIN fact_asset_scan_vulnerability_finding prev_finding 
    ON prev_scan.scan_id = prev_finding.scan_id 
    AND a.asset_id = prev_finding.asset_id
JOIN dim_vulnerability v ON prev_finding.vulnerability_id = v.vulnerability_id
LEFT JOIN fact_asset_scan_vulnerability_finding curr_finding 
    ON last_scan.scan_id = curr_finding.scan_id 
    AND a.asset_id = curr_finding.asset_id 
    AND prev_finding.vulnerability_id = curr_finding.vulnerability_id
-- Optional: Join with solution
LEFT JOIN dim_asset_vulnerability_best_solution vbs 
    ON (a.asset_id = vbs.asset_id AND v.vulnerability_id = vbs.vulnerability_id)
LEFT JOIN dim_solution s ON vbs.solution_id = s.solution_id
-- Only include vulnerabilities that have been reduced in count
WHERE (prev_finding.vulnerability_instances > COALESCE(curr_finding.vulnerability_instances, 0))
-- Add filter for scans within the last 7 days
AND last_scan.scan_finished >= (CURRENT_DATE - INTERVAL '7 days')
ORDER BY 
    remediation_status, 
    instances_difference DESC, 
    a.host_name, 
    v.severity_score DESC;
ORDER BY a.host_name, v.severity_score DESC;
