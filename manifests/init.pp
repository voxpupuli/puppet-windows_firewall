# Class windows_firewall
#
# This class manages the windows firewall
#
# Parameters:
#   [*ensure*]          - Control the state of the windows firewall
#
# Actions:
#
# Requires:
#
# Usage:
#
#   class { 'windows_firewall': 
#     ensure => present,
#   }
class windows_firewall(
	$ensure = 'running'
) {

    service { 'MpsSvc': 
      ensure => $ensure,
      enable => true,
    }
    
    registry::value { 'EnableFirewall':
      key   => 'HKLM\SYSTEM\ControlSet001\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile',
      value => 'EnableFirewall',
      type  => 'dword',
      data  => '1'
    }
}