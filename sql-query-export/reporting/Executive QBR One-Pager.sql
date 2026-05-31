-- Executive QBR One-Pager
-- Single-row executive roll-up: asset count, total risk, severity breakdown,
-- exploitable findings, and authentication / agent coverage percentages.
-- Optionally scope to a business unit by editing the tag prefix filter.

WITH scope AS (
    -- Assets in scope. Remove the tag join/filter to report on all assets.
    SELECT DISTINCT fa.asset_id
    FROM fact_asset fa
    JOIN dim_tag_asset dta ON dta.asset_id = fa.asset_id
    JOIN dim_tag dt        ON dt.tag_id = dta.tag_id
    WHERE dt.tag_name LIKE 'YOUR-TAG-PREFIX-%'
),
risk AS (
    SELECT
        SUM(fa.riskscore)                AS total_risk,
        SUM(fa.critical_vulnerabilities) AS critical_vulns,
        SUM(fa.severe_vulnerabilities)   AS severe_vulns,
        SUM(fa.moderate_vulnerabilities) AS moderate_vulns
    FROM fact_asset fa
    JOIN scope s ON s.asset_id = fa.asset_id
),
exploitable AS (
    SELECT COUNT(DISTINCT favf.asset_id || ':' || favf.vulnerability_id) AS exploitable_findings
    FROM fact_asset_vulnerability_finding favf
    JOIN scope s ON s.asset_id = favf.asset_id
    JOIN dim_vulnerability dv ON dv.vulnerability_id = favf.vulnerability_id
    WHERE dv.exploits > 0
),
auth AS (
    SELECT
        COUNT(*) AS total_assets,
        SUM(CASE WHEN dacs.aggregated_credential_status_description
                 IN ('All credentials successful','Credentials partially successful')
                 THEN 1 ELSE 0 END) AS authenticated_assets
    FROM fact_asset fa
    JOIN scope s ON s.asset_id = fa.asset_id
    JOIN dim_aggregated_credential_status dacs
        ON dacs.aggregated_credential_status_id = fa.aggregated_credential_status_id
),
agent AS (
    SELECT COUNT(DISTINCT daui.asset_id) AS agent_assets
    FROM dim_asset_unique_id daui
    JOIN scope s ON s.asset_id = daui.asset_id
    WHERE daui.source = 'R7 Agent'
)
SELECT
    auth.total_assets                                   AS assets,
    ROUND(risk.total_risk::numeric, 0)                  AS total_risk_score,
    risk.critical_vulns,
    risk.severe_vulns,
    risk.moderate_vulns,
    exploitable.exploitable_findings,
    ROUND(100.0 * auth.authenticated_assets
          / NULLIF(auth.total_assets, 0), 0)            AS pct_authenticated,
    ROUND(100.0 * agent.agent_assets
          / NULLIF(auth.total_assets, 0), 0)            AS pct_with_agent
FROM risk, exploitable, auth, agent;
