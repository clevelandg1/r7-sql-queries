-- Risk Summary by Firm
-- One row per business unit with total assets, risk score and severity counts.
-- Firm identity is derived by mapping site and asset-group name prefixes to a
-- canonical firm name. The firm_name_map below is a TEMPLATE — replace the example rows with your own prefixes.

WITH firm_name_map AS (
    -- TEMPLATE: replace the example rows below with your own site / asset-group
    -- name prefixes. The query matches on the first word of each site/group name
    -- and can refine with the 2nd-4th words for sub-units. Add as many rows as needed.
    SELECT raw_prefix, second_word, third_word, fourth_word, firm_name
    FROM (VALUES
        -- raw_prefix    2nd word   3rd word   4th word   canonical firm_name
        ('ExampleA',     NULL,      NULL,      NULL,      'Example Unit A'),
        ('ExampleB',     NULL,      NULL,      NULL,      'Example Unit B'),
        ('ExampleC',     'East',    NULL,      NULL,      'Example Unit C - East'),
        ('ExampleC',     'West',    NULL,      NULL,      'Example Unit C - West')
    ) AS t(raw_prefix, second_word, third_word, fourth_word, firm_name)
),

filtered_sites AS (
    SELECT ds.site_id, fnm.firm_name
    FROM dim_site ds
    JOIN firm_name_map fnm
        ON split_part(ds.name, ' ', 1) = fnm.raw_prefix
        AND (fnm.second_word IS NULL OR split_part(ds.name, ' ', 2) = fnm.second_word)
        AND (fnm.third_word IS NULL OR split_part(ds.name, ' ', 3) = fnm.third_word)
        AND (fnm.fourth_word IS NULL OR split_part(ds.name, ' ', 4) = fnm.fourth_word)
),

filtered_groups AS (
    SELECT dag.asset_group_id, fnm.firm_name
    FROM dim_asset_group dag
    JOIN firm_name_map fnm
        ON split_part(dag.name, ' ', 1) = fnm.raw_prefix
        AND (fnm.second_word IS NULL OR split_part(dag.name, ' ', 2) = fnm.second_word)
        AND (fnm.third_word IS NULL OR split_part(dag.name, ' ', 3) = fnm.third_word)
        AND (fnm.fourth_word IS NULL OR split_part(dag.name, ' ', 4) = fnm.fourth_word)
),

firm_assets AS (
    SELECT fs.firm_name, dsa.asset_id
    FROM filtered_sites fs
    JOIN dim_site_asset dsa USING (site_id)

    UNION

    SELECT fg.firm_name, daga.asset_id
    FROM filtered_groups fg
    JOIN dim_asset_group_asset daga USING (asset_group_id)
),

firm_asset_metrics AS (
    SELECT DISTINCT ON (fa_grouped.firm_name, fa_grouped.asset_id)
        fa_grouped.firm_name,
        fa_grouped.asset_id,
        fa.riskscore,
        fa.critical_vulnerabilities,
        fa.severe_vulnerabilities,
        fa.moderate_vulnerabilities
    FROM firm_assets fa_grouped
    JOIN fact_asset fa ON fa.asset_id = fa_grouped.asset_id
)

SELECT
    firm_name,
    COUNT(asset_id)                                  AS total_assets,
    ROUND(SUM(riskscore)::numeric, 0)                AS total_risk_score,
    SUM(critical_vulnerabilities)                    AS critical_vulns,
    SUM(severe_vulnerabilities)                      AS severe_vulns,
    SUM(moderate_vulnerabilities)                    AS moderate_vulns
FROM firm_asset_metrics
GROUP BY firm_name
ORDER BY total_risk_score DESC;
