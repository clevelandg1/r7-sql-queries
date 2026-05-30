-- Scan Assistant Status
-- Scan Assistant credential status per asset from the most recent scan only,
-- identified by the Scan Assistant listener on TCP port 21047.

-- Scan Assistant status from the latest scan only (port 21047)
SELECT
    fass.asset_id,
    dcs.credential_status_description AS scan_assistant_status,
    fass.port AS scan_assistant_port
FROM fact_asset fa
JOIN fact_asset_scan_service fass
    ON fa.asset_id = fass.asset_id
   AND fa.last_scan_id = fass.scan_id      -- pin to most recent scan
JOIN dim_credential_status dcs
    ON fass.credential_status_id = dcs.credential_status_id
WHERE fass.port = 21047;
