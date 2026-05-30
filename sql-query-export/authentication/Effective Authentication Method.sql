-- Effective Authentication Method
-- One row per asset combining the three authentication paths InsightVM can use
-- (Scan Assistant, Insight Agent, traditional credentials) into a single derived
-- effective_auth_method; assets with none are flagged 'NO AUTHENTICATION'.

WITH scan_assistant_status AS (
    SELECT
        fass.asset_id,
        dcs.credential_status_description AS scan_assistant_status,
        fass.port AS scan_assistant_port
    FROM fact_asset fa
    JOIN fact_asset_scan_service fass
        ON fa.asset_id = fass.asset_id
       AND fa.last_scan_id = fass.scan_id
    JOIN dim_credential_status dcs
        ON fass.credential_status_id = dcs.credential_status_id
    WHERE fass.port = 21047
),
agent_presence AS (
    SELECT DISTINCT asset_id, 'Yes' AS insight_agent_installed
    FROM dim_asset_unique_id
    WHERE source = 'R7 Agent'
),
traditional_creds AS (
    SELECT
        dasc.asset_id,
        COUNT(CASE WHEN dasc.credential_status_id IN (3,4,5,6) THEN 1 END) AS trad_success_count,
        COUNT(CASE WHEN dasc.credential_status_id = 2 THEN 1 END)         AS trad_failed_count,
        COUNT(CASE WHEN dasc.credential_status_id = 1 THEN 1 END)         AS trad_no_creds_count,
        STRING_AGG(
            CASE WHEN dasc.credential_status_id = 2
                 THEN ds.name || ' (' || dp.name || '/' || dasc.port || ')'
            END, ', ' ORDER BY dasc.port
        ) AS trad_failed_services_ports,
        STRING_AGG(
            CASE WHEN dasc.credential_status_id IN (3,4,5,6)
                 THEN ds.name || ' (' || dp.name || '/' || dasc.port || ')'
            END, ', ' ORDER BY dasc.port
        ) AS trad_successful_services_ports
    FROM dim_asset_service_credential dasc
    JOIN dim_service ds  ON dasc.service_id  = ds.service_id
    JOIN dim_protocol dp ON dasc.protocol_id = dp.protocol_id
    GROUP BY dasc.asset_id
)
SELECT
    da.ip_address,
    da.host_name,
    dos.description AS operating_system,
    dacs.aggregated_credential_status_description AS traditional_cred_status,
    COALESCE(sa.scan_assistant_status, 'Not Detected') AS scan_assistant_status,
    COALESCE(ap.insight_agent_installed, 'No')         AS insight_agent_installed,
    CASE
        WHEN sa.scan_assistant_status = 'Login Successful'
             THEN 'Scan Assistant'
        WHEN ap.insight_agent_installed = 'Yes'
             AND dacs.aggregated_credential_status_description IN ('All credentials successful','Credentials partially successful')
             THEN 'Agent + Traditional Creds'
        WHEN ap.insight_agent_installed = 'Yes'
             THEN 'Insight Agent Only'
        WHEN dacs.aggregated_credential_status_description = 'All credentials successful'
             THEN 'Traditional Creds'
        WHEN dacs.aggregated_credential_status_description = 'Credentials partially successful'
             THEN 'Traditional Creds (Partial)'
        WHEN sa.scan_assistant_status IS NOT NULL
             THEN 'Scan Assistant ('||sa.scan_assistant_status||')'
        ELSE 'NO AUTHENTICATION'
    END AS effective_auth_method,
    tc.trad_success_count,
    tc.trad_failed_count,
    tc.trad_no_creds_count,
    tc.trad_failed_services_ports,
    tc.trad_successful_services_ports,
    STRING_AGG(DISTINCT CASE WHEN dt.tag_name LIKE 'YOUR-BU-PREFIX-%'
                             THEN dt.tag_name END, ', ') AS business_unit
FROM fact_asset fa
JOIN dim_asset da
    ON fa.asset_id = da.asset_id
JOIN dim_aggregated_credential_status dacs
    ON fa.aggregated_credential_status_id = dacs.aggregated_credential_status_id
LEFT JOIN dim_operating_system dos
    ON da.operating_system_id = dos.operating_system_id
LEFT JOIN scan_assistant_status sa
    ON da.asset_id = sa.asset_id
LEFT JOIN agent_presence ap
    ON da.asset_id = ap.asset_id
LEFT JOIN traditional_creds tc
    ON da.asset_id = tc.asset_id
LEFT JOIN dim_tag_asset dta
    ON da.asset_id = dta.asset_id
LEFT JOIN dim_tag dt
    ON dta.tag_id = dt.tag_id
GROUP BY
    da.ip_address, da.host_name, dos.description,
    dacs.aggregated_credential_status_description,
    sa.scan_assistant_status,
    ap.insight_agent_installed,
    tc.trad_success_count, tc.trad_failed_count, tc.trad_no_creds_count,
    tc.trad_failed_services_ports, tc.trad_successful_services_ports
ORDER BY
    CASE
        WHEN sa.scan_assistant_status = 'Login Successful' THEN 5
        WHEN ap.insight_agent_installed = 'Yes' THEN 4
        WHEN dacs.aggregated_credential_status_description = 'All credentials successful' THEN 3
        WHEN dacs.aggregated_credential_status_description = 'Credentials partially successful' THEN 2
        ELSE 1
    END,
    da.ip_address;
