# Author::    Liam Bennett (mailto:liamjbennett@gmail.com)
# Copyright:: Copyright (c) 2014 Liam Bennett
# License::   MIT

# == Class: windows_firewall
#
# Module to manage the windows firewall and it's configured exceptions
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
# === Examples
#
# To ensure that windows_firwall is running:
#
#   class { 'windows_firewall':
#     ensure => 'running',
#   }
#
class windows_firewall (
    $ensure = 'running'
) {

    validate_re($ensure,['^(running|stopped)$'])

    case $::operatingsystemversion {
        /Windows Server 2003/,/Windows Server 2003 R2/,/Windows XP/: {
          $firewall_name = 'SharedAccess'
        }
        default: {
          $firewall_name = 'MpsSvc'
        }
    }

    case $ensure {
        'running': {
            $enabled = true
            $enabled_data = '1'
        }
        default: {
            $enabled = false
            $enabled_data = '0'
        }
    }

    service { 'windows_firewall':
      ensure => $ensure,
      name   => $firewall_name,
      enable => $enabled,
    }

    registry_value { 'EnableFirewall':
      ensure => 'present',
      path   => '32:HKLM\SYSTEM\ControlSet001\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall',
      type   => 'dword',
      data   => $enabled_data
    }
}
