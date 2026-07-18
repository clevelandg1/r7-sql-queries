# R7 SQL Queries

This repository contains SQL queries for InsightVM reports and data analysis, organized by category.

## Folder Structure

```
sql-query-export/
├── agent-health/
├── asset-management/
├── authentication/
├── reporting/
├── scan-health/
└── vulnerability-tracking/
```

## Query Index

### agent-health

| File | Description |
|------|-------------|
| [Agent Health Status.sql](sql-query-export/agent-health/Agent%20Health%20Status.sql) | Reports agent check-in times and classifies each asset as Active, Stale (7+ days), or No Agent |
| [Insight Agent Status Report.sql](sql-query-export/agent-health/Insight%20Agent%20Status%20Report.sql) | Alternative agent status view using last assessment date as a proxy for agent check-in, with owner and scan engine details |
| [Insight Agent ID Export.sql](sql-query-export/agent-health/Insight%20Agent%20ID%20Export.sql) | Exports the Rapid7 Insight Agent unique ID for every agent-installed asset (source = 'R7 Agent') |
| [Agent vs Scan Coverage Matrix.sql](sql-query-export/agent-health/Agent%20vs%20Scan%20Coverage%20Matrix.sql) | Classifies every asset as Agent Only, Scan Only, Both, or Neither using agent presence (source = 'R7 Agent') and scan history, with percentage of fleet |
| [Stale Coverage Gap (No Recent Agent and No Recent Scan).sql](sql-query-export/agent-health/Stale%20Coverage%20Gap%20%28No%20Recent%20Agent%20and%20No%20Recent%20Scan%29.sql) | Blind-spot assets with no completed scan and no recent agent assessment inside a configurable staleness window (default 30 days), classified by gap_reason |

### asset-management

| File | Description |
|------|-------------|
| [Browser Extension Report.sql](sql-query-export/asset-management/Browser%20Extension%20Report.sql) | Inventories browser extensions and plugins detected across all assets using broad name/family/vendor pattern matching |
| [Duplicate Assets.sql](sql-query-export/asset-management/Duplicate%20Assets.sql) | Finds hostnames assigned to more than one asset ID, which may indicate duplicate records |
| [Software Inventory and EOL Report.sql](sql-query-export/asset-management/Software%20Inventory%20and%20EOL%20Report.sql) | Comprehensive software inventory with risk classification highlighting End-of-Support and high-risk software versions |
| [Operating System EOL Inventory.sql](sql-query-export/asset-management/Operating%20System%20EOL%20Inventory.sql) | Lists assets on obsolete/end-of-life operating systems using Rapid7's built-in "Obsolete" vulnerability category (not hard-coded version patterns), grouped by OS with asset counts |

### authentication

| File | Description |
|------|-------------|
| [Scan Assistant Status.sql](sql-query-export/authentication/Scan%20Assistant%20Status.sql) | Scan Assistant credential status per asset from the most recent scan, identified by the listener on TCP port 21047 |
| [Effective Authentication Method.sql](sql-query-export/authentication/Effective%20Authentication%20Method.sql) | Combines Scan Assistant, Insight Agent, and traditional credentials into one derived effective_auth_method per asset; flags assets with NO AUTHENTICATION |
| [Credential Coverage Scorecard by Site.sql](sql-query-export/authentication/Credential%20Coverage%20Scorecard%20by%20Site.sql) | Per-site scorecard of authenticated vs. unauthenticated assets and percentage successfully authenticated, from aggregated credential status |
| [Unauthenticated Assets.sql](sql-query-export/authentication/Unauthenticated%20Assets.sql) | Lists assets whose aggregated credential status is not successful, so scans could not fully authenticate, with site and IP |

### reporting

| File | Description |
|------|-------------|
| [Scan Audit Report.sql](sql-query-export/reporting/Scan%20Audit%20Report.sql) | Shows the most recent scan status per site over the past 30 days and flags sites with no recent successful scans |
| [Top 25 Remediations with Details.sql](sql-query-export/reporting/Top%2025%20Remediations%20with%20Details.sql) | Lists the top 25 remediation actions ranked by impacted asset count and risk score reduction, including exploit/malware metrics |
| [Monthly Vulnerability Summary by Tag.sql](sql-query-export/reporting/Monthly%20Vulnerability%20Summary%20by%20Tag.sql) | QBR roll-up of vulnerabilities and risk score by tag, one row per tag per month |
| [Monthly Vulnerability Summary by Business Unit.sql](sql-query-export/reporting/Monthly%20Vulnerability%20Summary%20by%20Business%20Unit.sql) | QBR roll-up by business-unit tag prefix, one row per unit per calendar month |
| [Risk Summary by Firm.sql](sql-query-export/reporting/Risk%20Summary%20by%20Firm.sql) | One row per business unit with total assets, risk score and severity counts, derived from site/group name prefixes |
| [Risk Detail by Firm and Asset.sql](sql-query-export/reporting/Risk%20Detail%20by%20Firm%20and%20Asset.sql) | Asset-level drill-down behind the per-firm summary, one row per asset |
| [Mean Time To Remediate by Severity.sql](sql-query-export/reporting/Mean%20Time%20To%20Remediate%20by%20Severity.sql) | Average and median days from first discovery to inferred remediation, per severity, with min/max |
| [Accepted-Risk Exception Exposure Summary.sql](sql-query-export/reporting/Accepted-Risk%20Exception%20Exposure%20Summary.sql) | Risk masked by approved, non-expired vulnerability exceptions, grouped by exception reason, with vulnerabilities de-duplicated so risk is not double-counted |
| [Executive QBR One-Pager.sql](sql-query-export/reporting/Executive%20QBR%20One-Pager.sql) | Single-row executive roll-up: asset count, total risk, severity counts, exploitable findings, % authenticated, and % with agent (optional tag scope) |
| [Remediation Velocity Trend (New vs Fixed Monthly).sql](sql-query-export/reporting/Remediation%20Velocity%20Trend%20(New%20vs%20Fixed%20Monthly).sql) | Monthly gross new vulnerability findings vs. remediations, with net change; trailing 12 months |
| [Vulnerabilities Remediated Within SLA.sql](sql-query-export/reporting/Vulnerabilities%20Remediated%20Within%20SLA.sql) | Counts remediated findings inside vs. outside a 30-day SLA, with remediation inferred from scan history (seen historically, absent from current open findings) and days-open measured first-to-last observed scan |
| [Best Solution Per Vulnerability Per Asset.sql](sql-query-export/reporting/Best%20Solution%20Per%20Vulnerability%20Per%20Asset.sql) | For each currently-open vulnerability finding, the single best (rollup/superseding) recommended solution per asset, with solution type, time estimate and remediation URL (optional tag scope) |

### scan-health

| File | Description |
|------|-------------|
| [Scan Coverage vs Configured Targets.sql](sql-query-export/scan-health/Scan%20Coverage%20vs%20Configured%20Targets.sql) | Compares each site's configured included targets (dim_site_target) against assets that actually exist for the site, flagging configured host/IP targets with no matching live asset as coverage gaps (IP ranges flagged for manual review) |

### vulnerability-tracking

| File | Description |
|------|-------------|
| [Critical Vulnerabilities Older Than 30 Days.sql](sql-query-export/vulnerability-tracking/Critical%20Vulnerabilities%20Older%20Than%2030%20Days.sql) | Lists critical-severity vulnerabilities that have been open for more than 30 days, ordered by age |
| [Remediated Vulnerabilities - Last 7 Days.sql](sql-query-export/vulnerability-tracking/Remediated%20Vulnerabilities%20-%20Last%207%20Days.sql) | Tracks partial and full vulnerability remediations confirmed in the most recent scan within the last 7 days |
| [Remediated Vulnerabilities Between Last Two Scans.sql](sql-query-export/vulnerability-tracking/Remediated%20Vulnerabilities%20Between%20Last%20Two%20Scans.sql) | Finds vulnerabilities present in the previous scan that are absent from the most recent scan, confirming remediation |
| [Top 10 Assets with Most Critical Vulnerabilities.sql](sql-query-export/vulnerability-tracking/Top%2010%20Assets%20with%20Most%20Critical%20Vulnerabilities.sql) | Returns the ten assets with the highest count of critical vulnerability findings |
| [Monthly Vulnerabilities per Asset - Rolling 3 Months.sql](sql-query-export/vulnerability-tracking/Monthly%20Vulnerabilities%20per%20Asset%20-%20Rolling%203%20Months.sql) | Per-asset monthly snapshots over the trailing ~3 months via fact_asset_date() |
| [Monthly Vulnerabilities per Asset - 3 Calendar Months.sql](sql-query-export/vulnerability-tracking/Monthly%20Vulnerabilities%20per%20Asset%20-%203%20Calendar%20Months.sql) | Same per-asset monthly snapshots bounded to 3 clean calendar months |
| [Historical Vulnerability Trend by Tag.sql](sql-query-export/vulnerability-tracking/Historical%20Vulnerability%20Trend%20by%20Tag.sql) | Per-asset monthly snapshots over an explicit date range, scoped to a single tag |
| [Asset Vulnerability CVE Listing.sql](sql-query-export/vulnerability-tracking/Asset%20Vulnerability%20CVE%20Listing.sql) | Flat one-row-per-asset-per-CVE listing for export and downstream pivoting |
| [Weak Cipher Vulnerability Count by Asset.sql](sql-query-export/vulnerability-tracking/Weak%20Cipher%20Vulnerability%20Count%20by%20Asset.sql) | Counts distinct weak/insecure cipher vulnerabilities per asset |
| [Vulnerability SLA Compliance by Severity.sql](sql-query-export/vulnerability-tracking/Vulnerability%20SLA%20Compliance%20by%20Severity.sql) | Open vulnerabilities inside vs. outside severity-based remediation SLA windows, with a compliance % per severity |
| [Exploitable Vulnerabilities With Published Exploit.sql](sql-query-export/vulnerability-tracking/Exploitable%20Vulnerabilities%20With%20Published%20Exploit.sql) | Top 50 exploitable vulnerabilities ranked by affected asset count multiplied by risk score (ported from the Rapid7 community query) |
| [Threat-Prioritized Remediation Queue.sql](sql-query-export/vulnerability-tracking/Threat-Prioritized%20Remediation%20Queue.sql) | Ranks open vulnerabilities by a threat-priority score combining exploit availability, malware kits, severity, and affected asset count (optional tag scope) |
| [Vulnerability Aging Buckets by Severity.sql](sql-query-export/vulnerability-tracking/Vulnerability%20Aging%20Buckets%20by%20Severity.sql) | Counts open findings in 0-30 / 31-60 / 61-90 / 90+ day age buckets broken out by severity |
