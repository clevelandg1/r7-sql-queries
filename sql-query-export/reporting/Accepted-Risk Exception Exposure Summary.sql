-- Accepted-Risk Exception Exposure Summary
-- Summarizes risk masked by actively-applied vulnerability exceptions: only
-- Approved (status 'A') exceptions that have not expired are counted, grouped by
-- exception reason. Vulnerabilities are de-duplicated within each group so a vuln
-- with multiple exception records is not double-counted in the risk total.

WITH active_exceptions AS (
    -- Distinct vulnerabilities under an approved, non-expired exception, by reason
    SELECT DISTINCT
        der.description AS exception_reason,
        dve.vulnerability_id
    FROM dim_vulnerability_exception dve
    JOIN dim_exception_reason der ON der.reason_id = dve.reason_id
    JOIN dim_exception_status des ON des.status_id = dve.status_id
    WHERE des.status_id = 'A'                                      -- Approved / actively applied
      AND (dve.expiration_date IS NULL OR dve.expiration_date >= CURRENT_DATE)
)
SELECT
    ae.exception_reason,
    COUNT(*)                                AS distinct_vulnerabilities,
    ROUND(SUM(dv.riskscore)::numeric, 0)    AS accepted_risk_score
FROM active_exceptions ae
JOIN dim_vulnerability dv ON dv.vulnerability_id = ae.vulnerability_id
GROUP BY ae.exception_reason
ORDER BY accepted_risk_score DESC;
