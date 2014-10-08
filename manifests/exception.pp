# Author::    Liam Bennett (mailto:liamjbennett@gmail.com)
# Copyright:: Copyright (c) 2014 Liam Bennett
# License::   MIT

# == Define: windows_firewall::exception
#
# This defined type manages exceptions in the windows firewall
#
# === Requirements/Dependencies
#
# Currently reequires the puppetlabs/stdlib module on the Puppet Forge in
# order to validate much of the the provided configuration.
#
# === Parameters
#
# [*ensure*]
# Control the existence of a rule
#
# [*direction*]
# Specifies whether this rule matches inbound or outbound network traffic.
#
# [*action*]
# Specifies what Windows Firewall with Advanced Security does to filter network packets that match the criteria specified in this rule.
#
# [*enabled*]
# Specifies whether the rule is currently enabled.
#
# [*protocol*]
# Specifies that network packets with a matching IP protocol match this rule.
#
# [*remote_ip*]
# Specifies remote hosts that can use this rule.
#
# [*local_port*]
# Specifies that network packets with matching IP port numbers matched by this rule.
#
# [*display_name*]
# Specifies the rule name assigned to the rule that you want to display
#
# [*description*]
# Provides information about the firewall rule.
#
# [*allow_edge_traversal*]
# Specifies that the traffic for this exception traverses an edge device
#
# === Examples
#
#  Exception for protocol/port:
#
#   windows_firewall::exception { 'WINRM-HTTP-In-TCP':
#     ensure       => present,
#     direction    => 'in',
#     action       => 'Allow',
#     enabled      => 'yes',
#     protocol     => 'TCP',
#     local_port   => '5985',
#     remote_ip    => '10.0.0.1,10.0.0.2'
#     program      => undef,
#     display_name => 'Windows Remote Management HTTP-In',
#     description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
#   }
#
#  Exception for program path:
#
#   windows_firewall::exception { 'myapp':
#     ensure       => present,
#     direction    => 'in',
#     action       => 'Allow',
#     enabled      => 'yes',
#     program      => 'C:\\myapp.exe',
#     display_name => 'My App',
#     description  => 'Inbound rule for My App',
#   }
#
define windows_firewall::exception(
  $ensure = 'present',
  $direction = '',
  $action = '',
  $enabled = 'yes',
  $protocol = '',
  $local_port = '',
  $remote_ip = '',
  $program = undef,
  $display_name = '',
  $description = '',
  $allow_edge_traversal = 'no',

) {

    # Check if we're allowing a program or port/protocol and validate accordingly
    if $program == undef {
      #check whether to use 'localport', or just 'port' depending on OS
      case $::operatingsystemversion {
        /Windows Server 2003/, /Windows XP/: {
          $port_param = 'port'
        }
        default: {
          $port_param = 'localport'
        }
      }
      $fw_command = 'portopening'
      validate_re($protocol,['^(TCP|UDP|ICMPv(4|6))$'])
      if $protocol =~ /ICMPv(4|6)/ {
        $allow_context = "protocol=${protocol}"
      } else {
        $allow_context = "protocol=${protocol} ${port_param}=${local_port}"
        validate_re($local_port,['any|[0-9]{1,5}'])
      }
    } else {
      $fw_command = 'allowedprogram'
      $allow_context = "program=\"${program}\""
      validate_absolute_path($program)
    }

    # Validate common parameters
    validate_re($ensure,['^(present|absent)$'])
    validate_slength($display_name,255)
    validate_re($enabled,['^(yes|no)$'])
    validate_re($allow_edge_traversal,['^(yes|no)$'])

    case $::operatingsystemversion {
      'Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Vista','Windows 7','Windows 8': {
        validate_slength($description,255)
        validate_re($direction,['^(in|out)$'])
        validate_re($action,['^(allow|block)$'])
      }
      default: { }
    }

    # Set command to check for existing rules
    $check_rule_existance= "C:\\Windows\\System32\\netsh.exe advfirewall firewall show rule name=\"${display_name}\""

    # Use unless for exec if we want the rule to exist, include a description
    if $ensure == 'present' {
        $fw_action = 'add'
        $unless = $check_rule_existance
        $onlyif = undef
        $fw_description = "description=\"${description}\""
    } else {
    # Or onlyif if we expect it to be absent; no description argument
        $fw_action = 'delete'
        $onlyif = $check_rule_existance
        $unless = undef
        $fw_description = ''
    }

    case $::operatingsystemversion {
      /Windows Server 2003/, /Windows XP/: {
        $mode = $enabled ? {
          'yes' => 'ENABLE',
          'no'  => 'DISABLE',
        }
        $netsh_command = "C:\\Windows\\System32\\netsh.exe firewall ${fw_action} ${fw_command} name=\"${display_name}\" mode=${mode} ${allow_context}"
      }
      default: {
        $netsh_command = "C:\\Windows\\System32\\netsh.exe advfirewall firewall ${fw_action} rule name=\"${display_name}\" ${fw_description} dir=${direction} action=${action} enable=${enabled} edge=${allow_edge_traversal} ${allow_context} remoteip=\"${remote_ip}\""
      }
    }

    exec { "set rule ${display_name}":
      command  => $netsh_command,
      provider => windows,
      onlyif   => $onlyif,
      unless   => $unless,
    }
}
