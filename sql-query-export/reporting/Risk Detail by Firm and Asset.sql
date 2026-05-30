-- Risk Detail by Firm and Asset
-- Asset-level drill-down behind the per-firm summary: one row per asset with its
-- firm, host, IP, risk score and severity counts. Self-contained (reproduces the
-- firm-mapping CTEs); keep firm_name_map in sync with Risk Summary by Firm.

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

asset_details AS (
    SELECT
        fa.asset_id,
        da.host_name,
        CAST(da.ip_address AS text)      AS ip_address,
        ROUND(fa.riskscore::numeric, 0)  AS risk_score,
        fa.critical_vulnerabilities      AS critical_vulns,
        fa.severe_vulnerabilities        AS severe_vulns,
        fa.moderate_vulnerabilities      AS moderate_vulns
    FROM fact_asset fa
    JOIN dim_asset da USING (asset_id)
)

SELECT
    firm_assets.firm_name,
    asset_details.asset_id,
    asset_details.host_name,
    asset_details.ip_address,
    asset_details.risk_score,
    asset_details.critical_vulns,
    asset_details.severe_vulns,
    asset_details.moderate_vulns
FROM firm_assets
JOIN asset_details ON asset_details.asset_id = firm_assets.asset_id
ORDER BY
    firm_assets.firm_name,
    asset_details.risk_score DESC;
