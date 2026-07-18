-- Certificate or Service Configuration Watchlist
-- Flags assets exposing insecure / cleartext network services (e.g. Telnet, SNMP v1/v2c)
-- and the credential outcome observed, ranked by asset CRITICALITY tag.
-- Note: the InsightVM data model has no certificate-expiry field, and
-- dim_asset_service_credential records credential status only for SNMP, SSH, Telnet and CIFS,
-- so this watches risky SERVICE configurations rather than certificate expiry.
-- EDIT the insecure_service VALUES list and the CRITICALITY tag filter to match your org.

WITH insecure_service AS (
    -- Template list of cleartext / weak-configuration service name patterns. Edit to taste.
    -- Telnet and SNMP are the ones that typically match the credentialed-service scope above.
    SELECT pattern FROM (VALUES
        ('telnet'),
        ('snmp'),
        ('ftp'),
        ('tftp'),
        ('rlogin'),
        ('rsh'),
        ('http'),
        ('vnc')
    ) AS s(pattern)
),
asset_criticality AS (
    -- Highest-weighted CRITICALITY tag per asset (an asset may carry more than one).
    SELECT asset_id, criticality, risk_modifier
    FROM (
        SELECT ta.asset_id,
               t.tag_name       AS criticality,
               t.risk_modifier,
               ROW_NUMBER() OVER (
                   PARTITION BY ta.asset_id
                   ORDER BY t.risk_modifier DESC NULLS LAST, t.tag_name
               ) AS rn
        FROM dim_tag_asset ta
        JOIN dim_tag t ON t.tag_id = ta.tag_id
        WHERE t.tag_type = 'CRITICALITY'
    ) ranked
    WHERE rn = 1
),
flagged_service AS (
    SELECT asc2.asset_id,
           svc.name   AS service_name,
           proto.name AS protocol,
           asc2.port,
           cs.credential_status_description AS credential_status,
           CASE
               WHEN cs.credential_status_id IN (3, 4, 5, 6)
                   THEN 'Login succeeded over cleartext / weak service'
               ELSE 'Cleartext / weak service exposed'
           END AS config_finding
    FROM dim_asset_service_credential asc2
    JOIN dim_service          svc   ON svc.service_id            = asc2.service_id
    JOIN dim_protocol         proto ON proto.protocol_id         = asc2.protocol_id
    JOIN dim_credential_status cs    ON cs.credential_status_id   = asc2.credential_status_id
    WHERE EXISTS (
        SELECT 1
        FROM insecure_service i
        WHERE svc.name ILIKE '%' || i.pattern || '%'
    )
)
SELECT a.host_name,
       a.ip_address,
       COALESCE(ac.criticality, 'Untagged')          AS criticality,
       ROUND(COALESCE(ac.risk_modifier, 1)::numeric, 2) AS criticality_weight,
       f.service_name,
       f.protocol,
       f.port,
       f.credential_status,
       f.config_finding
FROM flagged_service f
JOIN dim_asset a            ON a.asset_id  = f.asset_id
LEFT JOIN asset_criticality ac ON ac.asset_id = f.asset_id
ORDER BY COALESCE(ac.risk_modifier, 0) DESC, a.host_name, f.service_name, f.port;
