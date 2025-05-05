# Author::    Liam Bennett (mailto:liamjbennett@gmail.com)
# Copyright:: Copyright (c) 2014 Liam Bennett
# License::   MIT

# == Class: windows_firewall
#
# Module to manage the windows firewall and its configured exceptions
#
# === Requirements/Dependencies
#
# Currently reequires the puppetlabs/stdlib module on the Puppet Forge in
# order to validate much of the the provided configuration.
#
# === Parameters
#
# [*ensure*]
# Control the state of the windows firewall application
#
# [*exceptions*]
# Hash of exceptions to be created.
#
# === Examples
#
# To ensure that windows_firwall is running:
#
#   include windows_firewall
#
class windows_firewall (
  Stdlib::Ensure::Service $ensure = 'running',
  Hash $exceptions                = {},
) {
  $firewall_name = 'MpsSvc'

  if $ensure == 'running' {
    $enabled = true
    $enabled_data = '1'
  } else {
    $enabled = false
    $enabled_data = '0'
  }

  service { 'windows_firewall':
    ensure => $ensure,
    name   => $firewall_name,
    enable => $enabled,
  }

  registry_value { 'EnableFirewallDomainProfile':
    ensure => 'present',
    path   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall',
    type   => 'dword',
    data   => $enabled_data,
  }

  registry_value { 'EnableFirewallPublicProfile':
    ensure => 'present',
    path   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall',
    type   => 'dword',
    data   => $enabled_data,
  }

  registry_value { 'EnableFirewallStandardProfile':
    ensure => 'present',
    path   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall',
    type   => 'dword',
    data   => $enabled_data,
  }

  $exceptions.each |$exception, $attributes| {
    windows_firewall::exception { $exception:
      * => $attributes,
    }
  }
}
