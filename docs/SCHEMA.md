# InsightVM Reporting Data Model — Query Author Reference

Authoritative source: [`InsightVM-Reporting-Data-Model.txt`](InsightVM-Reporting-Data-Model.txt)
(the full Rapid7 Reporting Data Model dump). **Every query in this repo must use real
columns/tables from that file — verify column names there before writing or reviewing SQL.**

## Conventions (also enforced by the query-builder task)
- `dim_vulnerability.severity` is text: **Critical / Severe / Moderate** (not High/Med/Low).
- `dim_vulnerability.severity_score` and risk scores are 0–10 / numeric — ROUND risk scores to whole numbers.
- Prefer dimension tables and pre-aggregated functions over heavy joins on
  `fact_asset_scan_vulnerability_instance`. Narrow the base set before expensive joins.
- Avoid correlated / LATERAL subqueries — use windowed CTEs / ROW_NUMBER / anti-joins.
- Public repo: generic placeholders only (`YOUR-TAG-PREFIX-%`, etc.) — never real site/firm/host data.

## Frequently-used building blocks
- Current open findings: `fact_asset_vulnerability_finding` (asset_id, scan_id, vulnerability_id, vulnerability_instances) — accumulating snapshot, most recent scan only.
- Vulnerability age / remediation timing: `fact_asset_vulnerability_age` (asset_id, vulnerability_id, age_in_days, first_discovered, most_recently_discovered, reintroduced_date).
- Scan history per finding: `fact_asset_scan_vulnerability_finding`; scan dates live in `dim_scan` (started, finished, status, type), join on scan_id.
- Asset current state: `dim_asset` (asset_id, ip_address, host_name, mac_address, operating_system_id → dim_operating_system, host_type_id, sites, last_assessed_for_vulnerabilities).
- Trending over time: `fact_asset_date(startDate, endDate, dateInterval)` table-valued function.
- Remediation roll-ups: `fact_remediation(count, 'sort_col DESC')` table-valued function.
- Tag/BU scoping: `dim_tag_asset` + `dim_tag` (filter tag name by `YOUR-TAG-PREFIX-%`).

## Gotchas confirmed against the data model
- **No EOL/obsolete flag on `dim_operating_system`.** Its columns are operating_system_id,
  asset_type, description, vendor, family, name, version, architecture, system, cpe. There is
  NO boolean for end-of-life. To find obsolete/EOL platforms, use Rapid7's built-in **Obsolete**
  vulnerability category: join `dim_vulnerability_category` (category_id, vulnerability_id,
  category_name) where `category_name ILIKE '%obsolete%'`, then to `fact_asset_vulnerability_finding`.
  This is authoritative and self-updating with content releases — do not hard-code OS version lists.
  (See `asset-management/Operating System EOL Inventory.sql`.)
- `dim_vulnerability` has `title`, `severity` (Critical/Severe/Moderate), `severity_score` (0–10),
  cvss_v2/v3 fields, `exploits`, `malware_kits`, `denial_of_service`, `date_modified`.
- Agent presence is in `dim_asset_unique_id` where `source = 'R7 Agent'`.
- Credential status: `dim_aggregated_credential_status` (per asset) and `dim_credential_status` (per service).
- `of` is effectively reserved in PostgreSQL — don't use it as a table alias (use `obf`, etc.).

When adding or reviewing a query, open the full data model file above and confirm each table/column
exists and is used at its documented level of grain.
