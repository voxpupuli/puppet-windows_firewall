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
# Specifies that network packets with matching local IP port numbers matched by this rule.
#
# [*remote_port*]
# Specifies that network packets with matching remote IP port numbers matched by this rule.
#
# [*display_name*]
# Specifies the rule name assigned to the rule that you want to display. Defaults to the title of the resource.
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
#     action       => 'allow',
#     enabled      => true,
#     protocol     => 'TCP',
#     local_port   => 5985,
#     remote_port  => 'any',
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
#     action       => 'allow',
#     enabled      => true,
#     program      => 'C:\\myapp.exe',
#     display_name => 'My App',
#     description  => 'Inbound rule for My App',
#   }
#
define windows_firewall::exception (
  Enum['present', 'absent'] $ensure = 'present',
  Enum['in', 'out'] $direction = 'in',
  Enum['allow', 'block'] $action = 'allow',
  Boolean $enabled = true,
  Optional[Enum['TCP', 'UDP', 'ICMPv4', 'ICMPv6']] $protocol = undef,
  Windows_firewall::Port  $local_port  = undef,
  Windows_firewall::Port  $remote_port = undef,
  Optional[String] $remote_ip = undef,
  Optional[Stdlib::Windowspath] $program = undef,
  String[0, 255] $display_name = $title,
  String[0, 255] $description = '',
  Boolean $allow_edge_traversal = false,
) {
  # Check if we're allowing a program or port/protocol and validate accordingly
  if $program == undef {
    $local_port_param  = 'localport'
    $remote_port_param = 'remoteport'

    $fw_command = 'portopening'

    if $remote_port or $local_port {
      unless $protocol {
        fail 'Sorry, protocol is required, when defining local or remote port'
      }
    }

    if $protocol =~ /^ICMPv(4|6)/ {
      $allow_context = "protocol=${protocol}"
    } else {
      if $local_port {
        $local_port_cmd = "${local_port_param}=${local_port}"
      } else {
        $local_port_cmd = ''
      }

      if $remote_port {
        $remote_port_cmd = "${remote_port_param}=${remote_port}"
      } else {
        $remote_port_cmd = ''
      }

      # Strip whitespace that in case remore_port_cmd is empty
      $allow_context = rstrip("protocol=${protocol} ${local_port_cmd} ${remote_port_cmd}")
    }
  } else {
    $fw_command = 'allowedprogram'
    $allow_context = "program=\"${program}\""
  }

  # Set command to check for existing rules
  $netsh_exe = "${facts['os']['windows']['system32']}\\netsh.exe"
  $check_rule_existance= "${netsh_exe} advfirewall firewall show rule name=\"${display_name}\""

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

  $mode = $enabled ? {
    true  => 'yes',
    false => 'no',
  }
  $edge = $allow_edge_traversal ? {
    true  => 'yes',
    false => 'no',
  }

  if $fw_action == 'delete' and $program == undef {
    $netsh_command = "${netsh_exe} advfirewall firewall ${fw_action} rule name=\"${display_name}\" ${fw_description} dir=${direction} ${allow_context} remoteip=\"${remote_ip}\""
  } else {
    $netsh_command = "${netsh_exe} advfirewall firewall ${fw_action} rule name=\"${display_name}\" ${fw_description} dir=${direction} action=${action} enable=${mode} edge=${edge} ${allow_context} remoteip=\"${remote_ip}\""
  }
  #
  exec { "set rule ${display_name}":
    command  => $netsh_command,
    provider => windows,
    onlyif   => $onlyif,
    unless   => $unless,
  }
}
