# AMENDER – Automated CVE Exploitation Pipeline

**Slash command:** `/amender`
**Install path:** `<project-root>/.claude/commands/amender.md`

Run `/amender` from inside any clone of the AMENDER project.
The only lab-specific inputs are the **target URL** and **credentials** for
your local OpenEMR container. Everything else — PoC fetch, config build,
PoC synthesis, module generation, correction loops, logging — is handled
automatically.

---

## 1. Detect the project root

The project root is the directory that contains `src/`, `data/`, `modules/`,
and `logs/`. Locate it by walking up from the current working directory until
you find a directory containing all four. If you cannot find it, tell the user:

> "I can't find the AMENDER project root. Please `cd` into your openemr-lab
> directory (or any AMENDER project clone) and run `/amender` again."

All paths below are relative to this detected root. Never hardcode
`~/openemr-lab` or any absolute path.

---

## 2. Parse inputs

The user invokes this command with one of:
- `/amender CVE-2026-24849`
- `/amender CVE-2026-24849 --target http://192.168.1.50:8080`
- `/amender CVE-2026-24849 --target http://192.168.1.50:8080 --user admin`
- `/amender` (prompts for CVE interactively)

Extract:
- `CVE_ID` — the CVE identifier (e.g. `CVE-2026-24849`)
- `TARGET` — OpenEMR base URL (**no default** — always ask if not provided)
- `USER` — OpenEMR username (default: `admin`)
- `PROBE_FILE` — file to read as proof (default: `/etc/passwd`)
- `SITE` — OpenEMR site ID (default: `default`)
- `MAX_ITER_M3` — max correction iterations for M3 (default: `50`)
- `MAX_ITER_M5` — max correction iterations for M5 (default: `20`)

If `CVE_ID` is not provided, ask: "Which CVE should I run? (e.g. CVE-2026-24849)"

If `TARGET` is not provided, ask:
> "What is the URL of your local OpenEMR instance? (e.g. http://localhost:8080
> or http://192.168.X.X:8080)"

**Local-target rule:** verify `TARGET` resolves to `localhost`, `127.0.0.1`,
or a private RFC-1918 range (10.x, 172.16-31.x, 192.168.x). If it resolves
to a public IP, refuse and explain:
> "AMENDER only runs against local lab instances. The target you provided
> appears to be a public IP. Please use your isolated lab container."

---

## 3. Resolve the CVE config

Compute `cve_slug` = CVE_ID lowercased with hyphens replaced by underscores
(e.g. `CVE-2026-24849` → `cve_2026_24849`).

Look for `data/<cve_slug>.json`.

**If the config exists:** read it, extract `edb` and `vuln_class`, and proceed
to Step 4.

**If the config does NOT exist:** build it automatically — do NOT ask the user
for any of these values; look them up yourself:

### 3a. Find the EDB number

Fetch the Exploit-DB search page for this CVE:

```
https://www.exploit-db.com/search?cve=<CVE_ID without the "CVE-" prefix>
```

Parse the HTML (or JSON response) to extract the EDB ID — it appears as a
numeric link in the results table. If multiple entries exist, pick the one
with the highest ID (most recent).

If the search page is unreachable, try:
```
https://www.exploit-db.com/search?cve=<full CVE_ID>
```

### 3b. Fetch the EDB entry (for analysis)

Download the EDB entry to a temp location so you can read it:

```bash
mkdir -p data/pocs
curl -fsSL "https://www.exploit-db.com/raw/<EDB>" -o data/pocs/<EDB>.py
```

Read the downloaded file.

### 3c. Determine vuln_class from the EDB content

Read the advisory/PoC text and classify the vulnerability:

| vuln_class    | Indicators in the advisory/PoC                                         |
|---------------|------------------------------------------------------------------------|
| `file_read`   | file_get_contents, readfile(), fread(), docid param, mode=get, path traversal / arbitrary file disclosure |
| `rce_upload`  | file upload + exec, move_uploaded_file, shell via uploaded .php        |
| `sqli`        | SQL injection, UNION SELECT, sqlmap, blind injection                   |
| `ssrf`        | Server-Side Request Forgery, internal URL fetch                        |
| `xxe`         | XML External Entity, DOCTYPE, SYSTEM entity                            |

Set `vuln_class` to the best match. If uncertain, set to `"unknown"` and note
it in `"_notes"`.

### 3d. Extract generic config fields from the EDB content

Analyze the advisory/PoC code to extract every field. These fields are
**generic** — they describe the vulnerability mechanism without assuming any
specific module or endpoint:

| Config field       | What to look for                                                   |
|--------------------|--------------------------------------------------------------------|
| `name`             | Title in script docstring or advisory header (no `<`, use "prior to X.Y.Z") |
| `description`      | Docstring or top-level comment block                               |
| `disclosure_date`  | Date in comments or EDB page (YYYY-MM-DD)                         |
| `edb`              | EDB number found in Step 3a                                        |
| `vuln_class`       | Determined in Step 3c                                              |
| `vuln_endpoint`    | The vulnerable URL path (e.g. `/portal/import_template.php`)      |
| `vuln_method`      | HTTP method (`POST`, `GET`)                                        |
| `vuln_params`      | Key-value pairs sent to trigger the vulnerability; use `{{probe_file}}` as placeholder for the target file path |
| `auth_endpoint`    | URL path for login POST                                            |
| `auth_params`      | Login POST fields; use `{{user}}`, `{{password}}`, `{{site}}` as placeholders |
| `confirm_pattern`  | String in the response that proves exploitation (e.g. `root:x:0:0`) |
| `fail_markers`     | Strings that indicate auth failure or redirect to login            |
| `default_username` | Default username (usually `admin`)                                 |
| `default_filepath` | Default probe file (usually `/etc/passwd`)                         |
| `target_uri`       | Base path (usually `/`)                                            |

Also add standard fields:
```json
"cve":              "<CVE_ID>",
"module_type":      "auxiliary",
"author":           "AMENDER / Rezwanul Haque",
"default_password": "",
"references":       [["CVE", "<year-number>"], ["EDB", "<EDB>"]],
"login_params": {
  "new_login_session_management": "1",
  "authProvider": "Default",
  "languageChoice": "1"
}
```

**msftidy rules for `name`:** no `<` character; use "prior to X.Y.Z" instead
of "< X.Y.Z". No URL-type references for Exploit-DB; use `["EDB", "<id>"]`.

### 3e. Write the config

Write `data/<cve_slug>.json` using only the generic fields above.
Do NOT use module-specific or vendor-specific field names (no `faxsms_path`,
no `faxsms_actions`, or similar). Every config must follow the same schema
regardless of which OpenEMR module or endpoint is vulnerable.

If any field genuinely cannot be determined, set it to `""` and note it in
a top-level `"_notes"` key.

**Only ask the user** if the EDB entry cannot be fetched at all (network
failure, 404) — and even then, only ask for the EDB number. All other fields
come from the advisory/code.

---

## 4. Fetch or synthesize the PoC

Compute `poc_path` = `data/pocs/<EDB>.py`.

**Check if `poc_path` is a valid runnable Python file:**

```bash
head -5 data/pocs/<EDB>.py
```

A valid Python file starts with `#!/usr/bin/env python`, `import`, or a
Python docstring (`"""`). An advisory text file starts with `#` comment
blocks describing the vulnerability in prose, raw HTTP request examples,
or non-Python content.

**If the PoC is already valid Python** (including if Step 3 just downloaded
a real script): skip to Step 5.

**If the PoC does NOT exist:** fetch it:

```bash
mkdir -p data/pocs
curl -fsSL "https://www.exploit-db.com/raw/<EDB>" -o data/pocs/<EDB>.py
```

Then check again whether it is valid Python.

**If the downloaded file is advisory-only text (not runnable Python):**

Do NOT stop. Synthesize a minimal runnable PoC automatically:

1. Read the advisory text and the config you just built in Step 3.
2. Using `vuln_endpoint`, `vuln_method`, `vuln_params`, `auth_endpoint`,
   `auth_params`, `confirm_pattern`, and `fail_markers` from the config,
   write a Python script saved to `data/pocs/<EDB>.py` that:
   - Accepts `--target`, `--user`, `--password`, `--site`, `--probe-file`
     via `argparse` (matching the standard run_poc.py interface exactly).
   - Authenticates against `auth_endpoint` using `auth_params` (substituting
     `{{user}}`, `{{password}}`, `{{site}}` with actual values).
   - Sends the vulnerability request to `vuln_endpoint` using `vuln_method`
     and `vuln_params` (substituting `{{probe_file}}` with the `--probe-file`
     value).
   - Prints the response body to stdout on success.
   - Implements ONLY the read/confirm path — never write, delete, or execute.
   - Exits 0 if `confirm_pattern` is found in the response, exits 2 otherwise.
3. Preserve the original advisory as `data/pocs/<EDB>.advisory.txt`.

The synthesized PoC must implement exactly the mechanism documented in the
advisory — the endpoint, HTTP method, and parameters must match what the
advisory describes. Do not invent a different attack path.

---

## 5. Prompt for password

Ask: "OpenEMR password for `<USER>` on `<TARGET>`?"
Store as `PASSWORD` in-session only. Never write it to any file.
Pass it via the `AMENDER_PASSWORD` environment variable when calling M3.

---

## 6. M1 — Run the PoC

```bash
cd <project-root>
python3 src/run_poc.py \
  --poc        data/pocs/<EDB>.py \
  --cve        <CVE_ID> \
  --target     <TARGET> \
  --user       <USER> \
  --password   <PASSWORD> \
  --site       <SITE> \
  --probe-file <PROBE_FILE>
```

| Exit code | Meaning | Next step |
|-----------|---------|-----------|
| 0 | CONFIRMED | Skip M3, go to Step 7 (M4) |
| 2 | Logic fail | Go to Step 6a (M3) |
| 3 | Env error | Stop and report — do not retry |
| 1 | Arg error | Stop and fix the invocation |

### 6a. M3 — PoC Correction Loop (only if M1 exits 2)

```bash
cd <project-root>
python3 src/run_poc.py ... 2>&1 | tee logs/training/last_run_error.txt
AMENDER_PASSWORD=<PASSWORD> python3 src/correct_poc.py \
  data/pocs/<EDB>.py \
  logs/training/last_run_error.txt \
  --cve        <CVE_ID> \
  --target     <TARGET> \
  --user       <USER> \
  --site       <SITE> \
  --probe-file <PROBE_FILE> \
  --max-iter   <MAX_ITER_M3>
```

| Exit code | Meaning | Next step |
|-----------|---------|-----------|
| 0 | CONFIRMED | Go to Step 7 (M4) |
| 2 | EXHAUSTED | Stop and report — pipeline ends here |
| 3 | Env error | Stop and report |

---

## 7. M4 — Generate Metasploit Module

The output filename is determined by `vuln_class` from the config:

```bash
cd <project-root>
python3 src/generate_module.py \
  --config data/<cve_slug>.json \
  --out    modules/
```

The generated file will be named `modules/openemr_<cve_slug>_<vuln_class>.rb`
(e.g. `openemr_cve_2018_15142_file_read.rb`, `openemr_cve_2018_15139_rce_upload.rb`).

| Exit code | Meaning | Next step |
|-----------|---------|-----------|
| 0 | Both gates pass | Go to Step 7b (live test) |
| 2 | Gate(s) fail | Go to Step 7a (M5) |
| 3 | Env error | Stop and report |

### 7a. M5 — Module Correction Loop (only if M4 exits 2)

```bash
cd <project-root>
python3 src/correct_module.py \
  modules/openemr_<cve_slug>_<vuln_class>.rb \
  logs/training/last_module_error.txt \
  --cve      <CVE_ID> \
  --max-iter <MAX_ITER_M5>
```

| Exit code | Meaning | Next step |
|-----------|---------|-----------|
| 0 | Both gates pass | Go to Step 7b (live test) |
| 2 | EXHAUSTED | Stop and report |
| 3 | Env error | Stop and report |

### 7b. Live msfconsole Test (always run after M4 or M5 passes)

Determine the correct module path by finding the `.rb` file location:

```bash
find <project-root>/modules -name "openemr_<cve_slug>_<vuln_class>.rb" | head -1
```

The `use` path is the part after `modules/` with the `.rb` stripped, replacing
the first directory segment: `exploits/` → `exploit/`, `auxiliary/` → `auxiliary/`.

Run the live test and capture output:

```bash
cd <project-root>
msfconsole -q -x "loadpath $(pwd)/modules; \
  use <module_path>; \
  set RHOSTS <TARGET_HOST>; \
  set RPORT <TARGET_PORT>; \
  set USERNAME <USER>; \
  set PASSWORD <PASSWORD>; \
  run; exit" 2>&1 | tee logs/training/last_live_test.txt
```

Where `TARGET_HOST` and `TARGET_PORT` are parsed from `TARGET`.

**Parse the live test output:**

| Output contains | Meaning | Next step |
|----------------|---------|-----------|
| `CONFIRMED` or `Upload completed` or `RCE Confirmed` or `passwd` content | Live test PASS | Go to Step 8 (done) |
| `Upload failed` or `Session rejected` or `Authentication failed` or `Failed to` | Live test FAIL | Go to Step 7c (live-test correction) |
| Module not found / load error | Path error | Fix the `use` path and retry once |

### 7c. Live-Test Correction Loop (only if 7b fails)

Read `logs/training/last_live_test.txt` and the current module file. Diagnose
the runtime failure — common causes for each vuln_class:

**file_read:** missing `keep_cookies: true`, wrong endpoint path, CSRF token not sent.

**rce_upload:** missing GET to upload page before POST (to fetch CSRF token),
`csrf_token_form` field not included in multipart form, wrong Metasploit base
class (`Msf::Auxiliary` instead of `Msf::Exploit::Remote` for exploit modules),
missing `Targets`/`Platform`/`Arch` fields, method named `run` instead of
`exploit`.

**sqli:** blind injection timing wrong, UNION column count mismatch.

**ssrf / xxe:** content-type header missing, entity encoding wrong.

Apply the fix directly to the module file. Then re-run Step 7b. Repeat up to
`MAX_ITER_M5` total iterations (counting iterations from Step 7a). If the live
test still fails after `MAX_ITER_M5` total corrections, stop and report:

```
Live test failed after <N> correction iterations.
Last error: <last line of logs/training/last_live_test.txt>
Module file: modules/<path>/<filename>.rb
```

---

## 8. M7 — Refresh the dashboard

After every successful stage (M1, M3, M4, M5), run:

```bash
cd <project-root>
python3 src/dashboard.py \
  --log logs/training/amender.jsonl \
  --out logs/dashboard.html
```

This prints a terminal summary and writes/updates `logs/dashboard.html`.
If `src/dashboard.py` does not exist, skip this step silently.

---

## 9. Report final status

```
╔══════════════════════════════════════════════════════════╗
║  AMENDER – Pipeline Complete                             ║
╠══════════════════════════════════════════════════════════╣
║  CVE        : <CVE_ID>                                   ║
║  Vuln class : <vuln_class>                               ║
║  Target     : <TARGET>  (local lab)                      ║
║  PoC        : <CONFIRMED | SYNTHESIZED | CORRECTED in N> ║
║  Module     : <READY | CORRECTED in N iter(s)>           ║
║  .rb file   : modules/openemr_<cve_slug>_<vuln_class>.rb ║
║  Training   : logs/training/amender.jsonl                ║
║  Dashboard  : logs/dashboard.html                        ║
╚══════════════════════════════════════════════════════════╝
```

Then ask: "Would you like to load the module into msfconsole for a live test?"

If yes, provide the exact msfconsole commands using the detected project root
and the user's TARGET/USER/PROBE_FILE values.

---

## Rules (always enforced)

1. **Local targets only.** Refuse any TARGET that is not localhost, 127.0.0.1,
   or a private RFC-1918 address.

2. **No hardcoded paths.** All paths are relative to the detected project root.
   Never write `~/openemr-lab` or any machine-specific absolute path.

3. **Never write passwords to files.** PASSWORD lives only in `AMENDER_PASSWORD`
   env var and `--password` flag during the session.

4. **Never modify fetched PoC exploit logic.** The correction loop (M3) may
   fix bugs, but must never change the target URL, credentials, or core
   vulnerability mechanism unless those are the confirmed bug source.

5. **Stop on exit code 3.** Env errors are not retried automatically.

6. **Log everything.** Every stage appends to `logs/training/amender.jsonl`.
   Never delete or truncate that file.

7. **One CVE per invocation.** Run multiple CVEs sequentially with separate
   `/amender` calls, each reported independently.

8. **No module-specific field names in configs.** Config files must use only
   the generic schema fields (`vuln_endpoint`, `vuln_params`, `vuln_class`,
   etc.). Never introduce fields tied to a specific OpenEMR module
   (e.g. `faxsms_path`, `faxsms_actions`). The pipeline must be equally
   capable of handling any CVE regardless of which module or endpoint it
   targets.

9. **Synthesized PoCs implement read/confirm only.** When synthesizing a PoC
   from an advisory text, implement only the path that reads a file and
   confirms the vulnerability. Never implement write, delete, or code
   execution paths in a synthesized PoC, even if the advisory documents them.
