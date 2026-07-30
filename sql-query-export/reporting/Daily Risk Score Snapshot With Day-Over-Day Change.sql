-- Daily Risk Score Snapshot With Day-Over-Day Change
-- Org-wide risk score captured at a DAILY interval so remediation shows up the day
-- it happens; standard weekly/monthly risk-over-time trends miss intra-period drops.
-- Edit the start/end dates in fact_asset_date(...) below to change the window.

WITH daily AS (
    -- fact_asset_date emits one row per asset per day (state as of the most recent
    -- scan prior to each day); roll those up into one org-wide row per day.
    SELECT
        fad.day                                    AS snapshot_date,
        COUNT(DISTINCT fad.asset_id)               AS assets_assessed,
        ROUND(SUM(fad.riskscore)::numeric)         AS total_risk_score,
        ROUND(AVG(fad.riskscore)::numeric)         AS avg_risk_score_per_asset,
        SUM(fad.critical_vulnerabilities)          AS critical_vulns,
        SUM(fad.severe_vulnerabilities)            AS severe_vulns,
        SUM(fad.moderate_vulnerabilities)          AS moderate_vulns,
        SUM(fad.vulnerabilities)                   AS total_vulns,
        SUM(fad.vulnerabilities_with_exploit)      AS vulns_with_exploit,
        SUM(fad.vulnerabilities_with_malware_kit)  AS vulns_with_malware_kit
    FROM fact_asset_date(
             (CURRENT_DATE - INTERVAL '90 days')::date,  -- start date (edit)
             CURRENT_DATE,                                -- end date (edit)
             INTERVAL '1 day'                             -- daily granularity
         ) fad
    GROUP BY fad.day
)
SELECT
    snapshot_date,
    assets_assessed,
    total_risk_score,
    -- Negative change = risk went down (remediation); positive = risk introduced
    total_risk_score - LAG(total_risk_score) OVER (ORDER BY snapshot_date)
                                                  AS risk_change_vs_prior_day,
    ROUND(
        100.0 * (total_risk_score - LAG(total_risk_score) OVER (ORDER BY snapshot_date))
        / NULLIF(LAG(total_risk_score) OVER (ORDER BY snapshot_date), 0)
    , 1)                                          AS risk_pct_change_vs_prior_day,
    avg_risk_score_per_asset,
    critical_vulns,
    critical_vulns - LAG(critical_vulns) OVER (ORDER BY snapshot_date)
                                                  AS critical_change_vs_prior_day,
    severe_vulns,
    moderate_vulns,
    total_vulns,
    total_vulns - LAG(total_vulns) OVER (ORDER BY snapshot_date)
                                                  AS total_vulns_change_vs_prior_day,
    vulns_with_exploit,
    vulns_with_malware_kit
FROM daily
ORDER BY snapshot_date;
