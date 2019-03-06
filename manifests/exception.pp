# Author::    Liam Bennett (mailto:liamjbennett@gmail.com)
# Copyright:: Copyright (c) 2014 Liam Bennett
# License::   MIT

# == Define: windows_firewall::exception
#
# This defined type manages exceptions in the windows firewall
#
# === Requirements/Dependencies
#
# Currently requires the puppetlabs/stdlib module on the Puppet Forge in
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
define windows_firewall::exception(
  Enum['present', 'absent'] $ensure = 'present',
  Enum['in', 'out'] $direction = 'in',
  Enum['allow', 'block'] $action = 'allow',
  Boolean $enabled = true,
  Optional[
    Enum['TCP', 'UDP', 'ICMPv4', 'ICMPv6']
  ] $protocol = undef,
  Optional[
    Variant[
      Integer[1, 65535],
      Enum['any','RPC','RPC-EPMap'],
      Pattern[/\A[1-9]{1}\Z|[1-9]{1}[0-9,-]*[0-9]{1}\Z/]
    ]
  ] $local_port = undef,
  Optional[
    Variant[
      Integer[1, 65535],
      Enum['any'],
      Pattern[/\A[1-9]{1}\Z|[1-9]{1}[0-9,-]*[0-9]{1}\Z/]
    ]
  ]$remote_port = undef,
  Optional[String] $remote_ip = undef,
  Optional[String] $program = undef,
  String[0, 255] $display_name = '',
  String $description = 'windows_firewall::exception generated rule',
  Boolean $allow_edge_traversal = false,
) {

  if ($protocol =~ /^ICMPv(4|6)/) and ($remote_port or $local_port) {
    fail 'Sorry, local and/or remote ports are not needed when protocol is ICMP'
  }

  if ($protocol == 'UDP') and ($local_port in ['RPC','RPC-EPMap']){
    fail 'Sorry, RPC and RPC-EPMap local ports require TCP'
  }

  #check whether to use 'localport', or just 'port' depending on OS
  case $::operatingsystemversion {
    /Windows Server 2003/, /Windows XP/: {
      $local_port_param = 'port'
      unless empty($remote_port) {
        fail "Sorry, :remote_port param is not supported on ${::operatingsystemversion}"
      }
    }
    default: {
      $local_port_param  = 'localport'
      $remote_port_param = 'remoteport'
    }
  }

  if $remote_port or $local_port {
    unless $protocol {
      fail 'Sorry, protocol is required, when defining local or remote port'
    }
  }

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

  $protocol_cmd = "protocol=${protocol}"

  case $::operatingsystemversion {
    'Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Vista','Windows 7','Windows 8': {
      validate_slength($description,255)
    }
    default: { }
  }

  # Set command to check for existing rules
  $netsh_exe = "${facts['os']['windows']['system32']}\\netsh.exe"

  case $::operatingsystemversion {
    /Windows Server 2003/, /Windows XP/: {
      $mode = $enabled ? {
        true  => 'ENABLE',
        false => 'DISABLE',
      }
      if $program == undef {

        $fw_command = 'portopening'
        $allow_context = rstrip("${protocol_cmd} ${local_port_cmd}")
        $check_rule_existance= "${netsh_exe} firewall show portopening | find \"${display_name}\""

      } else {
        $fw_command = 'allowedprogram'
        $program_cmd = "program=\"${program}\""
        validate_absolute_path($program)
        $allow_context = $program_cmd
        $check_rule_existance= "${netsh_exe} firewall show allowedprogram | find \"${display_name}\""
      }
      $netsh_command = "${netsh_exe} firewall ${fw_action} ${fw_command} name=\"${display_name}\" mode=${mode} ${allow_context}"
    }
    default: {
      $check_rule_existance= "${netsh_exe} advfirewall firewall show rule name=\"${display_name}\""
      if $program   {
        $program_cmd = "program=\"${program}\""
        validate_absolute_path($program)
      }
      $allow_context = rstrip("${program_cmd} ${protocol_cmd} ${local_port_cmd} ${remote_port_cmd}")
      $mode = $enabled ? {
        true  => 'yes',
        false => 'no',
      }
      $edge = $allow_edge_traversal ? {
        true  => 'yes',
        false => 'no',
      }

      if $ensure != 'present' {
        $netsh_command = "${netsh_exe} advfirewall firewall delete rule name=\"${display_name}\""
      } else {
        $netsh_command = "${netsh_exe} advfirewall firewall add rule name=\"${display_name}\" description=\"${description}\" 
        dir=\"${direction}\" action=\"${action}\" enable=\"${mode}\" edge=\"${edge}\" ${allow_context} remoteip=\"${remote_ip}\" profile=\"Any\""
      }
    }
  }

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

  exec { "set rule ${display_name}":
    command  => $netsh_command,
    provider => windows,
    onlyif   => $onlyif,
    unless   => $unless,
  }
}
