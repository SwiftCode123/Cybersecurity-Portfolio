#  MITRE-Sigma Lookup Tool

CLI tool that maps MITRE ATT&CK techniques to associated mitigations, Sigma detection rules, and Atomic Red Team tests, allowing analysts to explore defensive controls, detection content, and attack emulation resources from a single interface
## Project Background

**MITRE ATT&CK** is a globally accessible knowledge base of adversary tactics and techniques. Security teams use it to understand attacker behaviors, plan defenses, and map observed activity in their networks.

**Sigma** is a generic and open signature format for SIEM (Security Information and Event Management) systems. It allows security teams to define detection rules once and convert them to different SIEM formats. By linking ATT&CK techniques to Sigma rules, analysts can quickly translate threat intelligence into actionable detection logic.

**Atomic Red Team** is an open-source library of ATT&CK-mapped tests that safely emulate adversary behaviors in real environments. Security teams use these tests to validate detections, assess defensive controls, and practice threat hunting against realistic attack techniques. By incorporating Atomic Red Team data alongside ATT&CK techniques, mitigations, and Sigma rules, analysts can better understand how an attack is performed, detected, and defended against.

## Project Specifications

**Input:**

- ATT&CK Technique ID (e.g., T1566)
- ATT&CK Technique Name (e.g., Phishing)
- ATT&CK Technique Description (e.g., Adversaries may send victims emails containing malicious)

**Output:**
- Technique name
- Technique description
- ATT&CK mitigations associated with the technique
- Sigma detection rules that reference the technique
- Atomic Red Team tests associated with the technique

## Features
- Execute the MITRE-Sigma Lookup Tool from anywhere in the terminal using a custom alias
- Export console output to files using Rich Console recording with optional `-o/--output` support
- Support bulk processing of ATT&CK techniques via comma-separated input or text file ingestion with per-technique report generation and structured output directories
- Integrated Atomic Red Team to display ATT&CK-mapped adversary emulation tests in a formatted table
- Built a Django web interface with search dashboard, backend integration, routing, and HTML templates for browser-based lookups
- Improved Sigma search performance using an inverted index and in-memory caching for fast `O(1)` technique lookups
- Added automatic updates for MITRE ATT&CK and Sigma data using GitPython with a single `--update` flag
- Enhanced search with partial matching on technique names and descriptions, including paginated results for large outputs
- Integrated Splunk SIEM using PySigma and Splunk SDK to convert Sigma rules into Splunk queries and deploy them as active alerts

### Dependencies
Python 3.9+

A Linux environment with Internet access

*Note this project can be done in other systems, however all instructions are intended for Linux and may need to be modified for other environments.*
	
## Setup Environment

The setup process has been automated with `setup.sh`, or you can follow these steps:

### 1. Create a virtual environment and activate it
```bash
python -m venv venv
source venv/bin/activate
```
### 2. Install libraries
```bash
pip install mitreattack-python pyyaml rich python-dotenv pysigma GitPython pysigma-backend-splunk splunk-sdk
```

<!--https://mitreattack-python.readthedocs.io/en/latest/
### 3. Download an ATT&CK STIX bundle file (enterprise)
```bash
curl https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json -o enterprise-attack.json
```
### 4. Clone SigmaHQ/sigma locally
```bash
git clone https://github.com/SigmaHQ/sigma.git
```
### 5. Create a hello world program in `lookup.py`
```bash
echo -e '#!/usr/bin/env python3\nprint("hello world")' > lookup.py
``` -->

## Example Usage
### Searching by Technique ID

```bash
python mitre-sigma-lookup-tool T1566
```

Below we can see the successful run for Technique ID `T1566`. This printed out a comprehensive description of what phishing is (adversaries sending malicious messages to gain access to victim systems, utilizing social engineering, spearphishing, malicious attachments, or links). It also displayed a mitigation table of how to defend against phising such as `Audit (M1047)`, `Network Intrusion Prevention (M1031)`, `Software Configuration (M1054)`, `Restrict Web-Based Content (M1021)`, `Antivirus/Antimalware (M1049)`, and `User Training (M1017)`. 

The Sigma rules tables describes the attempt to find code that can detect phishing attempts. For example, the script found files in the local folders, `proc_creation_win_office_outlook_execution_from_temp.yml and iso_phishing.yml` that contain the text `T15661`. We see one rule parsed named `Search-ms and WebDAV Suspicious Indicators in URL`

<img width="6412" height="10076" alt="mitre_ID" src="https://github.com/user-attachments/assets/e95e816f-8da4-4d50-b89d-1f8c3edd9075" />

### Searching by Technique name

```bash
python mitre-sigma-lookup-tool Masquerading
```

Instead of searching by Technique ID, we can also search by technique name. I chose `Masquerading (T1036)` where hackers disguise malicious files or activity as something completely harmless (like renaming a piece of malware to svchost.exe so it looks like a built-in Windows service). The mitigations and sigma rules are outputted as well and describe the ways to defend and detect these attacks

For example, we can see that one mitigation technique is `Code Signing (M1045)` where we ensure files have a valid digital signature so hackers can't easily fake standard system utilities

The sigma output shows us ways to detect this attack. In these rules `proc_creation_win_renamed_powershell.yml` and `proc_creation_win_renamed_psexec.yml` monitor Windows event logs to see if a process has been renamed to hide its identity

<p align="center">
  <img width="5367" height="16384" alt="mitre_name" src="https://github.com/user-attachments/assets/e3ebc8cc-aefc-4253-b852-c2c4aa461d4d" />
</p>

## Features Implemented

- Alias the program to create a custom command that is accessible anywhere
	- [Feature #1](mitre-sigma-lookup-tool/post-project-implementation-01-alias)	 
- Handle outputting to files
	- [Feature #2](mitre-sigma-lookup-tool/post-project-implementation-02-handle-file-output) 
- Handle bulk searches and outputs
	- [Feature #3](mitre-sigma-lookup-tool/post-project-implementation-03-bulk-search-output) 
- Integrate another open-source library mapped to MITRE ATT&CK
	- [Feature #4](mitre-sigma-lookup-tool/post-project-implementation-04-atomic-attack-lib) 
- Use Django to create a web interface (search bar & hosting the site)
	- [Feature #5](mitre-sigma-lookup-tool/post-project-implementation-05-django-web-interface)
- Improve the speed of Sigma searches 
	- [Feature #6](mitre-sigma-lookup-tool/post-project-implementation-06-sigma-speed-searches)
- Automatically update MITRE and Sigma (which are only accessed locally)
	- [Feature #7](mitre-sigma-lookup-tool/post-project-implementation-07-auto-mitre-sigma-updates)
- Make searching by name or description “smarter” 
	- [Feature #8](mitre-sigma-lookup-tool/post-project-implementation-08-smarter-search)
- Interface directly with other professional cybersecurity tools
	- Splunk - Open-source SIEM (could implement Sigma rules directly)
 		- [Feature #9](mitre-sigma-lookup-tool/post-project-implementation-09-splunk-integration)

## Future Features
- MITRE Caldera - Attack platform for launching TTPs in MITRE ATT&CK
- Metasploit - Tool for emulating attacker’s TTPs
