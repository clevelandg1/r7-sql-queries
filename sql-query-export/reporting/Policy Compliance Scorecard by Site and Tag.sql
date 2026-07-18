-- Policy Compliance Scorecard by Site and Tag
-- Pass/fail policy rule results and compliance % broken out by site and tag.
-- Counts only scored rules (role <> 'unscored', enabled); compliance is the
-- boolean result of each asset's most recent policy scan per rule.
-- Edit the tag-name filter (YOUR-TAG-PREFIX-%) to scope to your business units.

WITH scored_results AS (
    -- One row per (asset, rule) result from the most recent policy scan,
    -- limited to rules that actually count toward compliance scoring.
    SELECT
        fapr.asset_id,
        fapr.policy_id,
        fapr.rule_id,
        fapr.compliance
    FROM fact_asset_policy_rule fapr
    JOIN dim_policy_rule dpr
        ON  dpr.policy_id = fapr.policy_id
        AND dpr.rule_id   = fapr.rule_id
        AND dpr.scope     = fapr.scope
    WHERE dpr.role <> 'unscored'
      AND dpr.enabled = TRUE
),
asset_site AS (
    SELECT dsa.asset_id, dsite.name AS site_name
    FROM dim_site_asset dsa
    JOIN dim_site dsite ON dsite.site_id = dsa.site_id
),
asset_tag AS (
    SELECT dta.asset_id, dt.tag_name
    FROM dim_tag_asset dta
    JOIN dim_tag dt ON dt.tag_id = dta.tag_id
    -- Scope to your business-unit / criticality tags; edit the prefix as needed.
    WHERE dt.tag_name LIKE 'YOUR-TAG-PREFIX-%'
)
SELECT
    asite.site_name,
    atag.tag_name,
    COUNT(*)                                      AS rule_results_tested,
    COUNT(*) FILTER (WHERE sr.compliance)         AS passing_results,
    COUNT(*) FILTER (WHERE NOT sr.compliance)     AS failing_results,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE sr.compliance)
        / NULLIF(COUNT(*), 0)
    , 0)                                          AS pct_compliant
FROM scored_results sr
JOIN asset_site asite ON asite.asset_id = sr.asset_id
JOIN asset_tag  atag  ON atag.asset_id  = sr.asset_id
GROUP BY asite.site_name, atag.tag_name
ORDER BY pct_compliant ASC, rule_results_tested DESC;
