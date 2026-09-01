CSA63 – CAMPUS SOC THREAT DETECTION AND INCIDENT RESPONSE

PROJECT CONTENTS
----------------
soc_system_final.py
data/
output_demo.txt
reflection_300_500_words.txt
deliverable_checklist.txt
plagiarism_self_check.txt

RUN
---
Open this folder in VS Code.

Demo:
    py soc_system_final.py --demo

Interactive menu:
    py soc_system_final.py

DATASET
-------
The project uses the supplied six CSV files without changing their records:
- firewall_log.csv
- auth_log.csv
- ids_log.csv
- threat_intel_feed.csv
- dns_resolution_map.csv
- host_identity_map.csv

ACTUAL DATASET COUNTS
---------------------
Firewall records: 12
Authentication records: 9
IDS records: 8
Threat-intelligence indicators: 4
DNS mappings: 1
Host identity mappings: 3
Normalized SOC records: 29

EXPECTED DETECTION RESULT
-------------------------
Port scan: 1
Brute-force: 1
Malware beacon: 1
Phishing: 1
Multi-stage compromise: 1
Total incidents: 5
Highest-risk incident: MULTI_STAGE_COMPROMISE = 100/100

The demo automatically advances the highest-risk incident through all five
incident-response stages and then prints a structured report with supporting
evidence and lifecycle history.
