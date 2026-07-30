-- Software EOL Risk Roll-up by Business Unit
-- Rolls up end-of-life / obsolete SOFTWARE exposure per Business Unit (tag).
-- EOL is detected with Rapid7's authoritative "Obsolete" vulnerability category
-- (not hard-coded version lists). Edit the BU tag prefix and the OS-exclusion note below.

WITH bu_asset AS (
    -- Map each asset to ONE Business Unit tag. Edit the tag_name filter to match
    -- your BU tagging scheme (template shown: a 'YOUR-BU-PREFIX-' naming convention).
    SELECT asset_id, bu_name
    FROM (
        SELECT ta.asset_id,
               t.tag_name AS bu_name,
               ROW_NUMBER() OVER (PARTITION BY ta.asset_id ORDER BY t.tag_name) AS rn
        FROM dim_tag_asset ta
        JOIN dim_tag t ON t.tag_id = ta.tag_id
        WHERE t.tag_name ILIKE 'YOUR-BU-PREFIX-%'   -- <-- edit: your BU tag prefix
    ) ranked
    WHERE rn = 1
),
eol_vulns AS (
    -- EOL / obsolete SOFTWARE checks per Rapid7's built-in "Obsolete" category.
    -- Excludes operating-system obsolescence (use OS EOL Inventory for that);
    -- remove the title filter to include obsolete operating systems too.
    SELECT DISTINCT dv.vulnerability_id, dv.title
    FROM dim_vulnerability_category vc
    JOIN dim_vulnerability dv ON dv.vulnerability_id = vc.vulnerability_id
    WHERE vc.category_name ILIKE '%obsolete%'
      AND dv.title NOT ILIKE '%operating system%'
),
eol_findings AS (
    -- Current open findings for those checks, scoped to a BU
    SELECT ba.bu_name, favf.asset_id, favf.vulnerability_id, ev.title
    FROM fact_asset_vulnerability_finding favf
    JOIN eol_vulns ev ON ev.vulnerability_id = favf.vulnerability_id
    JOIN bu_asset ba  ON ba.asset_id = favf.asset_id
),
bu_totals AS (
    -- Denominator: all assets in each BU, plus total software packages enumerated
    SELECT ba.bu_name,
           COUNT(DISTINCT ba.asset_id)      AS bu_asset_count,
           COUNT(DISTINCT das.software_id)  AS software_packages_seen
    FROM bu_asset ba
    LEFT JOIN dim_asset_software das ON das.asset_id = ba.asset_id
    GROUP BY ba.bu_name
)
SELECT
    bt.bu_name                                   AS "Business Unit",
    bt.bu_asset_count                            AS "Assets In BU",
    COUNT(DISTINCT ef.asset_id)                  AS "Assets With EOL Software",
    ROUND(100.0 * COUNT(DISTINCT ef.asset_id)
          / NULLIF(bt.bu_asset_count, 0), 1)     AS "Pct Assets Affected",
    COUNT(ef.vulnerability_id)                   AS "Open EOL Findings",
    COUNT(DISTINCT ef.vulnerability_id)          AS "Distinct EOL Software Checks",
    bt.software_packages_seen                    AS "Software Packages Enumerated",
    string_agg(DISTINCT ef.title, '; ' ORDER BY ef.title)
        FILTER (WHERE ef.title IS NOT NULL)      AS "Example EOL Software"
FROM bu_totals bt
LEFT JOIN eol_findings ef ON ef.bu_name = bt.bu_name
GROUP BY bt.bu_name, bt.bu_asset_count, bt.software_packages_seen
ORDER BY "Assets With EOL Software" DESC, bt.bu_name;
