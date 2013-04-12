# Class windows_firewall::exception
#
# This class manages exceptions in the windows firewall
#
# Parameters:
#   [*ensure*]          - Control the existence of a rule
#   [*direction]        - Specifies whether this rule matches inbound or outbound network traffic.
#   [*action]           - Specifies what Windows Firewall with Advanced Security does to filter network packets that match the criteria specified in this rule.
#   [*enabled]          - Specifies whether the rule is currently enabled.
#   [*protocol]         - Specifies that network packets with a matching IP protocol match this rule.
#   [*local_port]       - Specifies that network packets with matching IP port numbers matched by this rule.
#   [*display_name]     - Specifies the rule name assigned to the rule that you want to display
#   [*key_name]         - Specifies the name of rule as it appears in the registry
#   [*description]      - Provides information about the firewall rule.
#
# Actions:
#
# Requires:
#
# Usage:
#
#   class { 'windows_firewall::exception':
#     ensure       => present,
#     direction    => 'in',
#     action       => 'Allow',
#     enabled      => 'yes',
#     protocol     => 'TCP',
#     port         => '5985',
#     key_name     => 'WINRM-HTTP-In-TCP',
#     display_name => 'Windows Remote Management HTTP-In',
#     description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
#   }
#
class windows_firewall::exception(
  $ensure = 'present',
  $direction = '',
  $action = '',
  $enabled = 'yes',
  $protocol = '',
  $local_port = '',
  $display_name = '',
  $key_name = '',
  $description = '',

) {
    $reg_key = 'HKLM\SYSTEM\ControlSet001\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    
    exec { "set rule ${display_name}":
      command   => "& C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"${display_name}\" description=\"${description}\" dir=${direction} action=${action} enable=${enabled} protocol=${protocol} localport=${local_port}",
      provider  => powershell,
      logoutput => true,
      unless    => "if (Get-Item -LiteralPath \'\\${reg_key}\' -ErrorAction SilentlyContinue).GetValue(\'${key_name}\')) { exit 1 }"
    }
}