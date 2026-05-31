-- Accepted-Risk Exception Exposure Summary
-- Summarizes vulnerabilities under active (non-expired) exceptions, grouped by
-- exception reason and status, with the accepted risk each group represents.
-- Adapted/genericized from the Rapid7 community accepted-risk exception query.

SELECT
    der.description                                     AS exception_reason,
    des.description                                     AS exception_status,
    COUNT(*)                                            AS exception_count,
    COUNT(DISTINCT dve.vulnerability_id)                AS distinct_vulnerabilities,
    ROUND(SUM(dv.riskscore)::numeric, 0)                AS accepted_risk_score
FROM dim_vulnerability_exception dve
JOIN dim_exception_reason der ON der.reason_id = dve.reason_id
JOIN dim_exception_status des ON des.status_id = dve.status_id
JOIN dim_vulnerability dv     ON dv.vulnerability_id = dve.vulnerability_id
WHERE dve.expiration_date IS NULL
   OR dve.expiration_date >= CURRENT_DATE
GROUP BY der.description, des.description
ORDER BY accepted_risk_score DESC;
