#!/usr/bin/env python3

# default libraries
import argparse
import re
import sys
from pathlib import Path
import yaml
import json

# library for pretty CLI output
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown

# library for Splunk and Sigma
import os
from dotenv import load_dotenv
import splunklib.client as client
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from collections import defaultdict

import urllib.request
# From the GitPython library
import git  

# Initialize environmental configs immediately
load_dotenv()

# Terminal object that captures ("records") and stores all printed text, colors, and styling
console = Console(record=True)

# library for accessing MITRE ATT&CK data
from mitreattack.stix20 import MitreAttackData

# For Splunk App generation
import shutil

ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
# T\d{4}        -> Matchs "T" followed by 4 digits so from T0000 to T9999
# (?:\.\d{3})?  -> Matches "." followed by 3 digits or nothing (.000 to .999), opt.
# re.IGNORECASE -> Makes the whole thing case insensative

# Takes messy user input and extracts the clean ID 
# For example, turning technique t1105! to T1105
def normalize_attack_id(attack_id_raw: str):
    if not attack_id_raw:
        return None
    m = ATTACK_ID_RE.search(attack_id_raw)
    return m.group(0).upper() if m else None

# Extracts the ID out of the MITRE data block
def get_attack_id(technique, query):
    ext = technique.get("external_references", [])
    if ext:
        for e in ext:
            if e.get("external_id") and e.get("external_id").upper().startswith("T"):
                attack_id = normalize_attack_id(e.get("external_id"))
                break

    if not attack_id:
        attack_id = normalize_attack_id(query)

    if not attack_id:
        console.print("[yellow]Could not determine ATT&CK ID for technique. Sigma scan skipped.[/yellow]")
        return

    return attack_id

# Verifies if the folder containing the detection rules exists on your computer
def get_sigma_root(sigma):
    sigma_root = Path(sigma)

    if not sigma_root.exists():
        console.print(f"[red]Sigma folder not found at {sigma_root}[/red]")
        return

    return sigma_root

# Process Arguments (what options the user can add)
def process_arguments():
    parser = argparse.ArgumentParser(description="Lookup the MITRE mitigations and the Sigma detections for any technique")

    parser.add_argument("query", nargs="*", help="One or more ATT&CK technique IDs (`T1564`) or names (`Phishing`) (comma or space separated)")

    # If user inputs a single text file or a folder name
    parser.add_argument("-f", "--file", help="Path to a text file containing a list of ATT&CK IDs (one per line)")
    parser.add_argument("-o", "--output-dir", default="reports", help="Directory folder where bulk reports will be saved")

    BASE_DIR = Path(__file__).resolve().parent
    
    # Specifies the MITRE ATT&CK STIX dataset file and points to a cloned Sigma rules repository
    parser.add_argument("--stix", default=str(BASE_DIR / "enterprise-attack.json"), help="Path to enterprise STIX JSON bundle")
    parser.add_argument("--sigma", default=str(BASE_DIR / "sigma"), help="Path to local Sigma repo (folder)")

    # Specifies where Atomic Red Team test definitions are stored
    parser.add_argument("--atomics", default=str(BASE_DIR / "atomic-red-team" / "atomics"), help="Path to the cloned Atomic Red Team atomics folder")

    # Update the ATT&CK STIX dataset and pull the latest Sigma rules
    parser.add_argument("--update", action="store_true", help="Automatically pull latest MITRE and Sigma updates before searching")

    return parser.parse_args()

# Global dictionary to hold the inverted index of Sigma rules
SIGMA_INDEX = {}

def build_sigma_index(sigma_root: Path):
    """
    Build the Sigma rule index by scanning all rule files once,
    extracting ATT&CK technique IDs and indexing rule metadata
    """
    global SIGMA_INDEX
    console.record = False
    console.print("[bold]Building Sigma rule index...[/bold]")
    console.record = True
    
    # Creates a reusable regex that finds MITRE ATT&CK technique IDs in text
    """
    Example
    T1059
    T1003
    T1059.001
    t1547.001
    """
    all_ids_re = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

    # Loop through files and process valid Sigma rule files
    for p in sigma_root.rglob("*"):
        if p.is_dir() or p.suffix.lower() not in (".yml", ".yaml", ".json"):
            continue

        if "deprecated" in p.parts or "unsupported" in p.parts:
            continue
    
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        # Find all ATT&CK IDs mentioned in this file
        found_ids = set(normalize_attack_id(tid) for tid in all_ids_re.findall(text))
        if not found_ids:
            continue

        # Parse metadata once per file (title and tags) 
        # for either YAML or JSON
        title = "(no title)"
        tags = None

        if p.suffix.lower() in (".yml", ".yaml"):
            try:
                docs = list(yaml.safe_load_all(text))
                for doc in docs:
                    if isinstance(doc, dict):
                        title = doc.get("title", title)
                        tags = doc.get("tags", tags)
                        break
            except Exception:
                pass
        elif p.suffix.lower() == ".json":
            try:
                j = json.loads(text)
                if isinstance(j, dict):
                    title = j.get("title", title)
                    tags = j.get("tags", tags)
            except Exception:
                pass

        tags_str = str(tags) if tags is not None else None
        match_entry = {"file": str(p), "title": title, "tags": tags_str}

        # Build the lookup table of ATT&CK IDs to Sigma rules
        """
        Conceptually it looks like this:
        {
            "T1059": [rule1, rule2],
            "T1003": [rule3],
        }
        """
        for attack_id in found_ids:
            if attack_id:
                if attack_id not in SIGMA_INDEX:
                    SIGMA_INDEX[attack_id] = []
                SIGMA_INDEX[attack_id].append(match_entry)
"""
    Translates the Sigma YAML rule into Splunk SPL and deploys it 
    to the remote Proxmox Splunk VM instance as a Saved Search
"""
def deploy_to_splunk(sigma_rule_path, rule_title):
    try:
        # Extracts the file name
        # Example: test.yml or .yaml
        console.print(f"[*] Translating Sigma rule: [dim]{os.path.basename(sigma_rule_path)}[/dim]...")
        
        # Read the YAML file
        """
        Example:
        title: Suspicious PowerShell
        logsource:
            product: windows
        detection:
            selection:
                Image: '*powershell.exe'
        """
        with open(sigma_rule_path, "r", encoding="utf-8") as f:
            rule_yaml = f.read()
            
        # Converts the raw YAML text into a Sigma object
        rule = SigmaRule.from_yaml(rule_yaml)
        backend = SplunkBackend()
        
        # Convert the rule mapping into a raw Splunk query string
        """
        Example:
        Image: '*powershell.exe'
        turns into
        Image="*powershell.exe"
        """
        spl_queries = backend.convert_rule(rule)
        if not spl_queries:
            console.print("[red] Failed to translate rule logic into Splunk SPL.[/red]")
            return False
            
        # Some Sigma rules can generate multiple Splunk queries
        # This takes the first one
        splunk_spl = spl_queries[0]
        console.print(f"[green] Successfully compiled SPL:[/green] [cyan]{splunk_spl}[/cyan]")

    except Exception as e:
        console.print(f"[red] Error during Sigma translation: {e}[/red]")
        return False

    # Gets the host, port and loads the login credentials
    try:
        host = os.getenv("SPLUNK_HOST")
        port = int(os.getenv("SPLUNK_PORT", 8089))
        user = os.getenv("SPLUNK_USER")
        password = os.getenv("SPLUNK_PASSWORD")

        if not all([host, user, password]):
            console.print("[red] Missing Splunk credentials in your .env file.[/red]")
            return False

        console.print(f"[*] Connecting to Splunk management API at [bold]{host}:{port}[/bold]...")
        
        # Establish an authenticated API session
        service = client.connect(
            host=host,
            port=port,
            username=user,
            password=password,
            autologin=True,
            verify=False
        )

        # Create the Saved Search Alert inside Splunk
        # Example: rule_title = "Suspicious PowerShell"
        # becomes SIGMA - Suspicious PowerShell
        clean_title = f"SIGMA - {rule_title}"
        
        # Check if the alert already exists to prevent duplication
        # If it exists, update the Splunk saved search with SPL generated from the YAML
        # Note: If the YAML does not change, the SPL remains the same
        # If it does not exist, create a new Splunk saved search
        if clean_title in service.saved_searches:
            console.print(f"[yellow] Alert '{clean_title}' already exists. Updating query logic...[/yellow]")
            service.saved_searches[clean_title].update(search=splunk_spl)
        else:
            console.print(f"[*] Creating live correlation search rule: [magenta]{clean_title}[/magenta]...")
            service.saved_searches.create(
                name=clean_title,
                search=splunk_spl,
                **{
                    "is_scheduled": 1,
                    "cron_schedule": "*/5 * * * *",
                    "alert_type": "number of events",
                    "alert_threshold": 0,
                    "alert_comparator": "greater than",
                    "alert.track":1,
                    "alert.actions": "webhook",
                    "action.webhook": 1,
                    "action.webhook.param.url": "https://httpbin.org/post"
                }
            )
            
        console.print(f"[bold green] SUCCESS: Rule deployed live to Proxmox Splunk VM. Check your dashboard [/bold green]")
        return True

    except Exception as e:
        console.print(f"[red] Connection/Deployment failed: {e}[/red]")
        return False

"""
This function generates a full cybersecurity technique report: 
It finds a MITRE ATT&CK technique from a query, retrieves its mitigations, 
searches for matching Sigma rules, pulls related Atomic Red Team tests, 
displays everything in formatted console tables, 
and optionally saves the entire report to a file named after the technique ID
"""
def generate_single_report(mitre, sigma_root, query, atomics_root, output_dir=None, is_bulk=False):

    console.record = False
    console._record_buffer.clear()
    
    # Look up the technique in MITRE ATT&CK data
    tech = find_technique(mitre, query)
    if not tech:
        console.print(f"[red]Technique '{query}' not found[/red]")
        return None, []

    console._record_buffer.clear()

    console.record = True
    console.print(f"\n[bold blue]=========================================[/bold blue]")
    console.print(f"[bold]Processing technique for:[/bold] {query}")

    print_technique_summary(tech)
    
    console.record = False
    console.print("\n[bold]Fetching mitigations from ATT&CK...[/bold]")
    console.record = True

    # Fetches defenses / mitigations
    mitigations = get_mitigations_for_technique(mitre, tech)
    print_mitigations(mitigations)
    
    console.record = False
    console.print("\n[bold]Scanning local Sigma repo for matching rules...[/bold]")
    console.record = True

    # Uses the index and finds sigma rules related to that technique
    attack_id = get_attack_id(tech, query)
    matches = lookup_sigma_in_index(attack_id) if attack_id else []
    print_sigma_matches(matches)
        
    console.record = False
    console.print("\n[bold]Fetching simulation tests from Atomic Red Team...[/bold]")
    console.record = True

    # Pulls attack simulation tests for that technique
    atomic_tests = get_atomic_tests(atomics_root, attack_id)
    
    # Prints the Atomic Red Team simulation tests for a given technique ID
    if atomic_tests:
        table = Table(title="Atomic Red Team Simulation Tests")
        table.add_column("Test Name", style="cyan")
        table.add_column("Supported Platforms", style="green")
        table.add_column("Executor Engine", style="magenta")

        for test in atomic_tests:
            # Gather test details from the YAML structure
            name = test.get("name", "Unnamed Test")
            platforms = ", ".join(test.get("supported_platforms", []))
            executor = test.get("executor", {}).get("name", "manual")
            
            table.add_row(name, platforms, executor)
        
        console.print(table)
    else:
        console.print("[yellow]No local Atomic Red Team tests found for this technique.[/yellow]")

    # Save output to a unique file if directory is provided
    if output_dir and attack_id:
        
        out_path = Path(output_dir)

        # Create the folder if it doesn't exist
        out_path.mkdir(exist_ok=True, parents=True)

        # Build the final filename like:
        # reports/T1566_report.txt
        file_target = out_path / f"{attack_id}_report.txt"

        console.save_text(str(file_target))
        console.print(f"\n[bold green] Saved to {file_target}[/bold green]")
        console._record_buffer.clear()

    return attack_id, matches

# Helper to convert a single Sigma rule file into a Splunk SPL string
def translate_sigma_to_spl(sigma_rule_path):
    try:
        with open(sigma_rule_path, "r", encoding="utf-8") as f:
            rule_yaml = f.read()
        rule = SigmaRule.from_yaml(rule_yaml)
        backend = SplunkBackend()
        spl_queries = backend.convert_rule(rule)
        return spl_queries[0] if spl_queries else None
    except Exception:
        return None
    
# Tells Splunk what the app is, who wrote it and 
# whether it should appear in the Splunk UI
def build_app_conf(author="Dhruv Tripathi"):
    return f"""[ui]
is_visible = 1
label = MITRE ATT&CK Automated Detection Pack

[launcher]
author = {author}
description = Automated security monitoring content generated from local Sigma and MITRE lookup tooling.
version = 1.0.0

[package]
id = TA-mitre-detection-pack
"""

# Loop over all Sigma rules forund for the techniques and 
# dump them into a single file and Splunk parses this file on 
# startup to instantiate all the alerts
"""
Example
{
    "title": "PowerShell Download",
    "attack_id": "T1059",
    "spl": "index=windows ..."
}
is turned into
[SIGMA - T1059 - PowerShell Download]
search = index=windows ...
"""
def build_savedsearches_conf(compiled_rules):
    conf_content = ""
    for rule in compiled_rules:
        clean_title = f"SIGMA - {rule['attack_id']} - {rule['title']}"
        escaped_spl = rule['spl']
        
        conf_content += f"""[{clean_title}]
search = {escaped_spl}
dispatch.earliest_time = -15m
dispatch.latest_time = now
cron_schedule = */5 * * * *
enable_sched = 1
alert_type = number of events
alert_threshold = 0
alert_comparator = greater than
counttype = number of events
alert.track = 1
alert.actions = webhook
alert.suppress = 1
alert.suppress.period = 1m
action.webhook = 1
action.webhook.param.url = https://httpbin.org/post
\n"""
    return conf_content

# Creating the dashboard template that loops through all the selected rules
# and builds a panel grid/summary log panel of alert firings
"""
Example
PowerShell Download      12 alerts
Credential Dumping        3 alerts
Lateral Movement          7 alerts
"""
from collections import defaultdict


def build_dashboard_xml(compiled_rules):
    grouped_techniques = defaultdict(list)

    for rule in compiled_rules:
        grouped_techniques[rule["attack_id"]].append(rule)

    technique_rows = ""

    for attack_id, rules in grouped_techniques.items():

        search_clauses = " OR ".join(
            [
                f'savedsearch_name="SIGMA - {r["attack_id"]} - {r["title"]}"'
                for r in rules
            ]
        )

        technique_rows += f"""
<row>
  <panel>
    <title>{attack_id} - Trigger Count (24h)</title>
    <single>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
({search_clauses})
| stats count
        ]]></query>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </search>
      <option name="underLabel">Total Triggers</option>
      <option name="useColors">1</option>
      <option name="rangeColors">["#2ECC71","#F1C40F","#E67E22","#E74C3C"]</option>
      <option name="rangeValues">[1,10,50]</option>
    </single>
  </panel>

  <panel>
    <title>{attack_id} - 7 Day Trend</title>
    <chart>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
({search_clauses})
| timechart span=6h count
        ]]></query>
        <earliest>-7d@d</earliest>
        <latest>now</latest>
      </search>

      <option name="charting.chart">line</option>
      <option name="charting.legend.placement">bottom</option>
    </chart>
  </panel>
</row>

<row>
  <panel>
    <title>{attack_id} - Top Rule</title>
    <table>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
({search_clauses})
| stats count by savedsearch_name
| sort -count
| head 5
        ]]></query>
        <earliest>-30d@d</earliest>
        <latest>now</latest>
      </search>
    </table>
  </panel>
</row>
"""

    dashboard_xml = f"""
<dashboard version="1.1" theme="dark">

<label>MITRE ATT&amp;CK Security Operations Dashboard</label>

<description>
Executive ATT&amp;CK monitoring dashboard generated from Sigma detections.
</description>

<!-- Overview of KPIs -->

<row>

  <panel>
    <title>Total Alert Triggers (24h)</title>
    <single>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
| stats count
        ]]></query>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </search>

      <option name="underLabel">Alerts Fired</option>
      <option name="useColors">1</option>
      <option name="rangeColors">["#2ECC71","#F1C40F","#E67E22","#E74C3C"]</option>
      <option name="rangeValues">[10,100,500]</option>
    </single>
  </panel>

  <panel>
    <title>Unique ATT&amp;CK Techniques</title>
    <single>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
| rex field=savedsearch_name "SIGMA - (?<technique>T\\d+(?:\\.\\d+)?)"
| stats dc(technique) as techniques
        ]]></query>
        <earliest>-30d@d</earliest>
        <latest>now</latest>
      </search>
    </single>
  </panel>

  <panel>
    <title>Most Active Technique</title>
    <single>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
| rex field=savedsearch_name "SIGMA - (?<technique>T\\d+(?:\\.\\d+)?)"
| stats count by technique
| sort -count
| head 1
| fields technique
        ]]></query>
        <earliest>-30d@d</earliest>
        <latest>now</latest>
      </search>
    </single>
  </panel>

</row>

<!-- Alert Trend -->

<row>
  <panel>
    <title>Alert Activity Trend</title>

    <chart>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
| timechart span=1h count
        ]]></query>

        <earliest>-7d@d</earliest>
        <latest>now</latest>
      </search>

      <option name="charting.chart">line</option>
      <option name="charting.legend.placement">bottom</option>
    </chart>
  </panel>
</row>

<!-- Top ATT&CK techniques -->

<row>

  <panel>
    <title>Top ATT&amp;CK Techniques</title>

    <chart>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
| rex field=savedsearch_name "SIGMA - (?<technique>T\\d+(?:\\.\\d+)?)"
| stats count by technique
| sort -count
| head 10
        ]]></query>

        <earliest>-30d@d</earliest>
        <latest>now</latest>
      </search>

      <option name="charting.chart">bar</option>
    </chart>

  </panel>

</row>

<!-- Top most triggered rules -->

<row>

  <panel>
    <title>Most Triggered Rules</title>

    <chart>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
| stats count by savedsearch_name
| sort -count
| head 10
        ]]></query>

        <earliest>-30d@d</earliest>
        <latest>now</latest>
      </search>

      <option name="charting.chart">bar</option>
    </chart>

  </panel>

</row>

<!-- Recent Alerts -->

<row>

  <panel>
    <title>Recent Detection Activity</title>

    <table>
      <search>
        <query><![CDATA[
index=_internal sourcetype=scheduler alert_actions="webhook"
| table _time savedsearch_name result_count
| sort -_time
        ]]></query>

        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </search>
    </table>

  </panel>

</row>

<!-- Technique Detail Sections -->

{technique_rows}

</dashboard>
"""

    return dashboard_xml

# Makes the app universally readable inside Splunk (System permission)
def build_default_meta():
    return """[default]
access = read : [ * ], write : [ admin ]
export = system
"""

def build_nav_xml():
    return """<nav color="#006D9C">
  <view name="search" default="true" />
  <view name="dashboards" />
  <view name="alerts" />
</nav>
"""

def export_splunk_app(compiled_rules, base_output_path="generated_splunk_apps"):
    app_dir = Path(base_output_path) / "TA-mitre-detection-pack"
    default_dir = app_dir / "default"
    views_dir = default_dir / "data" / "ui" / "views"
    nav_dir = default_dir / "data" / "ui" / "nav"
    metadata_dir = app_dir / "metadata"
    
    # Clean and build directory trees
    for folder in [views_dir, nav_dir, metadata_dir]:
        folder.mkdir(parents=True, exist_ok=True)
        
    # Write configuration files
    (default_dir / "app.conf").write_text(build_app_conf(), encoding="utf-8")
    (default_dir / "savedsearches.conf").write_text(build_savedsearches_conf(compiled_rules), encoding="utf-8")
    (nav_dir / "default.xml").write_text(build_nav_xml(), encoding="utf-8")
    (views_dir / "attack_dashboard.xml").write_text(build_dashboard_xml(compiled_rules), encoding="utf-8")
    (metadata_dir / "default.meta").write_text(build_default_meta(), encoding="utf-8")
    
    # Package it as a tar.gz / .spl file so it can be uploaded through the Splunk UI
    archive_name = shutil.make_archive(str(app_dir), 'gztar', root_dir=app_dir.parent, base_dir=app_dir.name)
    
    # Rename .tar.gz extension to .spl
    spl_app_package = Path(archive_name).with_suffix('.spl')
    Path(archive_name).rename(spl_app_package)
    
    print(f"[+] Clean Splunk App compilation complete. Download package: {spl_app_package}")

# Load Atomic Red Team tests for a specific MITRE technique
def get_atomic_tests(atomics_root, attack_id):

    # Construct the path to the specific technique folder 
    # Example: (atomic-red-team/atomics/T1057/T1057.yaml)
    yaml_path = Path(atomics_root) / attack_id / f"{attack_id}.yaml"
    
    if not yaml_path.exists():
        return []

    try:
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("atomic_tests", [])
    except Exception:
        return []

# Load MITRE Data
def load_mitre_data(stix_path):
    return MitreAttackData(stix_path)

def find_technique(mitre, query):
    """
    Searches MITRE data smartly with an interactive paginated menu
    """
    query_clean = query.strip().upper()
    
    # Search by single ATT&CK ID
    # Example: `T1059`
    m = ATTACK_ID_RE.search(query_clean)
    if m:
        attack_id = m.group(0)
        return mitre.get_object_by_attack_id(attack_id, "attack-pattern")

    # Search all MITRE techniques by keyword and return matches
    # Check if the query matches technique name and description and collect
    # the matches into a list
    console.print(f"[*] Searching ATT&CK for partial matches matching '[cyan]{query}[/cyan]'...")
    all_techniques = mitre.get_techniques(remove_revoked_deprecated=True)
    potential_matches = []

    for tech in all_techniques:
        name = tech.get("name", "").upper()
        desc = tech.get("description", "").upper()
        if query_clean in name or query_clean in desc:
            potential_matches.append(tech)

    if not potential_matches:
        return None

    if len(potential_matches) == 1:
        return potential_matches[0]

    # Paginated menu (25 results at a time)
    PAGE_SIZE = 25
    start_idx = 0
    total_matches = len(potential_matches)

    while True:
        end_idx = min(start_idx + PAGE_SIZE, total_matches)
        console.print(f"\n[yellow] Found {total_matches} potential techniques. Showing matches {start_idx + 1}-{end_idx}:[/yellow]")
        
        # Display the current page of options
        menu_table = Table(box=None)
        menu_table.add_column("Selection", style="magenta", justify="right")
        menu_table.add_column("ATT&CK ID", style="green")
        menu_table.add_column("Technique Name", style="cyan")
        
        for idx in range(start_idx, end_idx):
            tech = potential_matches[idx]
            ext_refs = tech.get("external_references", [{}])
            attack_id = ext_refs[0].get("external_id", "N/A") if ext_refs else "N/A"
            menu_table.add_row(f"[{idx + 1}]", attack_id, tech.get("name"))
            
        console.print(menu_table)

        # Lets the user type a number, `n` for next page or `b` for previous page
        prompt_options = f"{start_idx + 1}-{end_idx}"
        nav_hints = []
        if end_idx < total_matches:
            nav_hints.append("'[bold]n[/bold]' for next page")
        if start_idx > 0:
            nav_hints.append("'[bold]b[/bold]' for back page")
            
        nav_str = " or ".join(nav_hints)
        if nav_str:
            console.print(f"[dim]Navigation options: {nav_str}[/dim]")

        # Keeps looking until the user selects a input
        try:
            choice = input(f"\nEnter number or action ({prompt_options}): ").strip().lower()
            
            if choice == 'n' and end_idx < total_matches:
                start_idx += PAGE_SIZE
                continue
            elif choice == 'b' and start_idx > 0:
                start_idx -= PAGE_SIZE
                continue
            
            # Try to parse numeric selection
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < total_matches:
                return potential_matches[choice_idx]
            else:
                print(f"Invalid selection. Please choose a number between 1 and {total_matches}.")
        except ValueError:
            print("Please enter a valid number or navigation command (n/b).")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[red]Search canceled.[/red]")
            sys.exit(0)


# Get Mitigations for Technique
def get_mitigations_for_technique(mitre, technique):
    try:
        tech_stix_id = technique["id"]
        mitigations = mitre.get_mitigations_mitigating_technique(tech_stix_id)
        if isinstance(mitigations, dict):
            mitigations = [entry["object"] for entries in mitigations.values() for entry in entries]
        return mitigations
    except Exception:
        try:
            mapping = mitre.get_all_techniques_mitigated_by_all_mitigations()
            return mapping.get(technique["id"], [])
        except Exception:
            return []

# Search Sigma Data for Technique
def lookup_sigma_in_index(attack_id: str):
    """
    Looks up a technique in the index. If given a root technique (Example: T1036),
    it automatically includes matches for all of its sub-techniques (Example: T1036.001)
    """
    if not attack_id:
        return []
        
    attack_id = attack_id.upper()
    matches = []

    # Get exact matches
    if attack_id in SIGMA_INDEX:
        matches.extend(SIGMA_INDEX[attack_id])

    # If the query is a root technique, look for sub-techniques
    """
    Root technique: T1036
    Sub-techniques: T1036.001, T1036.002, etc. 
    """
    if "." not in attack_id:
        # Regex to match sub-techniques 
        # (Example: ^T1036\.\d{3}$) where it starts with `T1036.` 
        # followed by 3 digits
        sub_tech_pattern = re.compile(rf"^{re.escape(attack_id)}\.\d{{3}}$")
        
        # Scan the dictionary keys to find sub-techniques
        for indexed_id in SIGMA_INDEX.keys():
            if sub_tech_pattern.match(indexed_id):
                matches.extend(SIGMA_INDEX[indexed_id])

    return matches

# Print Name & Description (MITRE) of Technqiue
def print_technique_summary(tech):
    name = tech.get("name", "Unknown")
    attack_id = tech.get("external_references", [{}])[0].get("external_id") \
                if tech.get("external_references") else None
    console.print(Markdown(f"# {name}  \n**STIX id:** {tech.get('id')}  \n**ATT&CK id:** {attack_id}"))
    desc = tech.get("description") or tech.get("x_mitre_short_description") or "(no description)"
    console.print(Markdown("### Description"))
    console.print(desc)

# Print Mitigations (MITRE) for Technqiue
def print_mitigations(mitigations):

    if not mitigations:
        console.print("\n[bold yellow]No mitigations found in ATT&CK dataset for this technique.[/bold yellow]\n")
        return
    
    # Create & fill the table
    table = Table(title="Mitigations from ATT&CK")
    table.add_column("Mitigation Name")
    table.add_column("ATT&CK id / STIX id")
    
    for m in mitigations:
        obj = m.get("object") if isinstance(m, dict) and "object" in m else m
        name = obj.get("name", "(no name)")
        ext = obj.get("external_references", [])
        ext_id = ext[0].get("external_id") if ext else obj.get("id")
        table.add_row(name, str(ext_id))
        
    console.print(table)

# Print Detections (SIGMA) for Technique
def print_sigma_matches(matches):

    if not matches:
        console.print("\n[bold yellow]No Sigma rules found referencing that technique in your sigma repo.[/bold yellow]\n")
        return
        
    # Create & fill the table
    table = Table(title="Sigma rules referencing technique")
    table.add_column("Title")
    table.add_column("File path", overflow="fold")
    table.add_column("Tags")
 
    for m in matches:
        table.add_row(str(m.get("title")), str(m.get("file")), str(m.get("tags")))
    
    console.print(table)

def run_auto_updates(stix_path: str, sigma_path: str):
    """
    Downloads the latest MITRE ATT&CK STIX data and pulls the newest Sigma rules
    """
    console.print("\n[bold yellow] Starting Automated Updates...[/bold yellow]")

    # Update MITRE ATT&CK STIX JSON
    mitre_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    console.print(f"[*] Fetching latest MITRE dataset from GitHub...")
    try:
        # Downloads the file directly and overwrites the local enterprise-attack.json
        urllib.request.urlretrieve(mitre_url, stix_path)
        console.print("[green] MITRE ATT&CK data updated successfully[/green]")
    except Exception as e:
        console.print(f"[red] Failed to update MITRE data: {e}[/red]")

    # Update Local Sigma Repository
    sigma_dir = Path(sigma_path)
    if sigma_dir.exists() and os.path.exists(os.path.join(sigma_path, ".git")):
        folder_name = Path(sigma_path).name
        console.print(f"[*] Pulling latest Sigma rules inside '{folder_name}'...")
        try:
            # Opens the existing local repository and calls origin pull
            repo = git.Repo(sigma_path)
            origin = repo.remotes.origin
            origin.pull()
            console.print("[green] Local Sigma repository updated successfully[/green]")
        except Exception as e:
            console.print(f"[red] Failed to update Sigma repo: {e}[/red]")
    else:
        console.print(f"[yellow]⚠ Local Sigma Git repo not found at '{sigma_path}'. Skipping git pull.[/yellow]")

def main():
    # Get user input
    args = process_arguments()

    # If user asked for updates, run update process
    if args.update:
        run_auto_updates(args.stix, args.sigma)
    
    queries = []
    
    # Either a file input or a direct query input
    # Example: -f file.txt or -q T1059,T1003
    if args.file:
        file_path = Path(args.file)
        if file_path.exists():
            queries = [line.strip() for line in file_path.read_text().splitlines() if line.strip()]
        else:
            console.print(f"[red]Error: Input file '{args.file}' not found.[/red]")
            sys.exit(1)
    elif args.query:
        # Join the list of inputs into a single string, splitting on commas
        """
        User input could be: T1059 T1003
        Join into one string and split by commas and result becomes
        ["T1059", "T1003"]
        """
        raw_query_string = ",".join(args.query)
        queries = [q.strip().upper() for q in raw_query_string.split(",") if q.strip()]
    elif args.update:
        console.print("[green] Update completed. No search query provided, exiting smoothly [/green]")
        sys.exit(0)
    else:
        console.print("[red]Error: You must provide a query technique or a text file via -f[/red]")
        sys.exit(1)

    console.record = False
    console.print("[bold]Loading ATT&CK data...[/bold]")
    console.record = True

    # Load MITRE ATT&CK dataset and find Sigma rule directory
    mitre = load_mitre_data(args.stix)
    sigma_root = get_sigma_root(args.sigma)

    console.record = False
    console.print(f"[bold green]Starting bulk processing for {len(queries)} techniques...[/bold green]")
    console.record = True

    # Build the memory index once before starting loop queries
    if sigma_root:
        build_sigma_index(sigma_root)
        
    # Check if this is a bulk run up front
    is_bulk_run = (len(queries) > 1 or bool(args.file))
        
    # Queue array to hold items for SIEM deployment queries
    pending_deployments = []

    for q in queries:
        output_folder = args.output_dir
        attack_id, matches = generate_single_report(mitre, sigma_root, q, output_dir=output_folder, atomics_root=args.atomics, is_bulk=is_bulk_run)
        
        if attack_id and matches:
            pending_deployments.append({"id": attack_id, "matches": matches})

    console.print("\n[bold green] All techniques processed successfully[/bold green]")

    # If the tool successfully matched detection patterns, prompt the deployment manager
    if pending_deployments:
        console.print(f"\n[bold blue]=========================================[/bold blue]")
        console.print("[bold]Deployment Action Options Menu:[/bold]")
        console.print("  [1] Interactive Deployment Queue (Push individual rules to live Splunk API)")
        console.print("  [2] Automated App Factory (Compile all matches into an installable Splunk App package)")
        console.print("  [3] Skip operational steps and exit")
        
        try:
            action_choice = input("\nSelect deployment choice (1-3): ").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
        
        # Go through every matched item and ask the user for deployment
        if action_choice == '1':
            for item in pending_deployments:
                attack_id = item["id"]
                matches = item["matches"]
                
                console.print(f"\n[bold yellow] Operational SIEM action available for {attack_id}[/bold yellow]")
                deploy_choice = input("Would you like to deploy any of these matched detection rules to your Splunk VM? (y/N): ").strip().lower()
                
                # If there is only one matching rule
                if deploy_choice == 'y':
                    if len(matches) == 1:
                        deploy_to_splunk(matches[0]["file"], matches[0]["title"])
                    else:
                        console.print("\n[yellow]Select which specific Sigma rule to push live to Proxmox:[/yellow]")
                        for idx, match in enumerate(matches, 1):
                            console.print(f"  [{idx}] {match['title']}")
                        
                        try:
                            rule_choice = input(f"\nEnter selection (1-{len(matches)}): ").strip()
                            rule_idx = int(rule_choice) - 1
                            if 0 <= rule_idx < len(matches):
                                deploy_to_splunk(matches[rule_idx]["file"], matches[rule_idx]["title"])
                            else:
                                print("Invalid selection number. Skipping deployment.")
                        except ValueError:
                            print("Invalid input. Skipping deployment.")
                            
        # Create an empty list, loop through every matched Sigma rule,
        # and convert each into a Splunk query search and create the Splunk App
        # package containing all translated rules
        elif action_choice == '2':
            console.print("\n[*] Initializing backend translation for all matched rules...")
            app_rules_pool = []
            
            for item in pending_deployments:
                attack_id = item["id"]
                for match in item["matches"]:
                    spl_query = translate_sigma_to_spl(match["file"])
                    if spl_query:
                        app_rules_pool.append({
                            "attack_id": attack_id,
                            "title": match["title"],
                            "spl": spl_query
                        })
            
            if app_rules_pool:
                export_splunk_app(app_rules_pool, args.output_dir)
            else:
                console.print("[red]No Sigma rules were successfully translated into SPL. App creation aborted.[/red]")
                
        else:
            console.print("[blue]Exiting search routine smoothly.[/blue]")

if __name__ == "__main__":
    main()