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
#   define { 'windows_firewall::exception':
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
define windows_firewall::exception(
  $ensure = 'present',
  $direction = '',
  $action = '',
  $enabled = 'yes',
  $protocol = '',
  $local_port = '',
  $display_name = '',
  $description = '',
  $key_name = '',

) {
    validate_re($ensure,['^(present|absent)$'])
    validate_slength($display_name,255)
    validate_re($enabled,['^(yes|no)$'])
    validate_re($protocol,['^(TCP|UDP)$'])
    validate_re($local_port,['[0-9]{1,5}'])
    validate_slength($key_name,255)

    case $::operatingsystemversion {
      'Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Vista','Windows 7','Windows 8': {
        validate_slength($description,255)
        validate_re($direction,['^(in|out)$'])
        validate_re($action,['^(allow|block)$'])
      }
      default: { }
    }

    if $ensure == 'present' {
        $fw_action = 'add'
    } else {
        $fw_action = 'delete'
    }

    if $::operatingsystemversion =~ /Windows Server 2003/ or $::operatingsystemversion =~ /Windows XP/ {
        if $enabled == 'yes' {
            $mode = 'ENABLE'
        } else {
            $mode = 'DISABLE'
        }
        exec { "set rule ${display_name}":
          command   => "C:\\Windows\\System32\\netsh.exe firewall ${fw_action} portopening name=\"${display_name}\" mode=${mode} protocol=${protocol} port=${local_port}",
          provider  => windows,
        }
    } else {
        exec { "set rule ${display_name}":
          command   => "C:\\Windows\\System32\\netsh.exe advfirewall firewall ${fw_action} rule name=\"${display_name}\" description=\"${description}\" dir=${direction} action=${action} enable=${enabled} protocol=${protocol} localport=${local_port}",
          provider  => windows,
        }
    }

}