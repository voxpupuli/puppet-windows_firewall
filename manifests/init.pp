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
# @param ensure
# [*ensure*]
# Control the state of the windows firewall application
#
# @param enable_domain_profile
# [*enable_domain_profile*]
# Enable the windows firewall "domain" profile
# Default depends on *ensure* parameter
#  running => true
#  stoppend => false
#
# @param enable_public_profile
# [*enable_public_profile*]
# Enable the windows firewall "public" profile
# Default depends on *ensure* parameter
#  running => true
#  stoppend => false
#
# @param enable_standard_profile
# [*enable_standard_profile*]
# Enable the windows firewall "standard" profile
# Default depends on *ensure* parameter
#  running => true
#  stoppend => false
#
# @param exceptions
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
  Stdlib::Ensure::Service $ensure                  = 'running',
  Optional[Boolean]       $enable_domain_profile   = undef,
  Optional[Boolean]       $enable_public_profile   = undef,
  Optional[Boolean]       $enable_standard_profile = undef,
  Hash                    $exceptions              = {},
) {
  $firewall_name = 'MpsSvc'

  if $ensure == 'running' {
    $enabled = true
  } else {
    $enabled = false
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
    data   => bool2num(pick($enable_domain_profile,$enabled)),
  }

  registry_value { 'EnableFirewallPublicProfile':
    ensure => 'present',
    path   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall',
    type   => 'dword',
    data   => bool2num(pick($enable_public_profile,$enabled)),
  }

  registry_value { 'EnableFirewallStandardProfile':
    ensure => 'present',
    path   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall',
    type   => 'dword',
    data   => bool2num(pick($enable_standard_profile,$enabled)),
  }

  $exceptions.each |$exception, $attributes| {
    windows_firewall::exception { $exception:
      * => $attributes,
    }
  }
}
