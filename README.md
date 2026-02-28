# R7 SQL Queries

This repository contains SQL queries for InsightVM reports and data analysis, organized by category.

## Folder Structure

```
sql-query-export/
├── agent-health/
├── asset-management/
├── reporting/
└── vulnerability-tracking/
```

## Query Index

### agent-health

| File | Description |
|------|-------------|
| [Agent Health Status.sql](sql-query-export/agent-health/Agent%20Health%20Status.sql) | Reports agent check-in times and classifies each asset as Active, Stale (7+ days), or No Agent |
| [Insight Agent Status Report.sql](sql-query-export/agent-health/Insight%20Agent%20Status%20Report.sql) | Alternative agent status view using last assessment date as a proxy for agent check-in, with owner and scan engine details |

### asset-management

| File | Description |
|------|-------------|
| [Browser Extension Report.sql](sql-query-export/asset-management/Browser%20Extension%20Report.sql) | Inventories browser extensions and plugins detected across all assets using broad name/family/vendor pattern matching |
| [Duplicate Assets.sql](sql-query-export/asset-management/Duplicate%20Assets.sql) | Finds hostnames assigned to more than one asset ID, which may indicate duplicate records |
| [Software Inventory and EOL Report.sql](sql-query-export/asset-management/Software%20Inventory%20and%20EOL%20Report.sql) | Comprehensive software inventory with risk classification highlighting End-of-Support and high-risk software versions |

### reporting

| File | Description |
|------|-------------|
| [Scan Audit Report.sql](sql-query-export/reporting/Scan%20Audit%20Report.sql) | Shows the most recent scan status per site over the past 30 days and flags sites with no recent successful scans |
| [Top 25 Remediations with Details.sql](sql-query-export/reporting/Top%2025%20Remediations%20with%20Details.sql) | Lists the top 25 remediation actions ranked by impacted asset count and risk score reduction, including exploit/malware metrics |

### vulnerability-tracking

| File | Description |
|------|-------------|
| [Critical Vulnerabilities Older Than 30 Days.sql](sql-query-export/vulnerability-tracking/Critical%20Vulnerabilities%20Older%20Than%2030%20Days.sql) | Lists critical-severity vulnerabilities that have been open for more than 30 days, ordered by age |
| [Remediated Vulnerabilities - Last 7 Days.sql](sql-query-export/vulnerability-tracking/Remediated%20Vulnerabilities%20-%20Last%207%20Days.sql) | Tracks partial and full vulnerability remediations confirmed in the most recent scan within the last 7 days |
| [Remediated Vulnerabilities Between Last Two Scans.sql](sql-query-export/vulnerability-tracking/Remediated%20Vulnerabilities%20Between%20Last%20Two%20Scans.sql) | Finds vulnerabilities present in the previous scan that are absent from the most recent scan, confirming remediation |
| [Top 10 Assets with Most Critical Vulnerabilities.sql](sql-query-export/vulnerability-tracking/Top%2010%20Assets%20with%20Most%20Critical%20Vulnerabilities.sql) | Returns the ten assets with the highest count of critical vulnerability findings |