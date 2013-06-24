Puppet module for managing the [Windows Firewall]().

This module is also available on the [Puppet Forge](https://forge.puppetlabs.com/liamjbennett/windows_firewall)

[![Build
Status](https://secure.travis-ci.org/liamjbennett/puppet-windows_firewall.png)](http://travis-ci.org/liamjbennett/puppet-windows_firewall)
[![Dependency
Status](https://gemnasium.com/liamjbennett/puppet-windows_firewall.png)](http://gemnasium.com/liamjbennett/puppet-windows_firewall)

## Configuration ##
The windows_firewall class has some defaults that can be overridden, for instance if you wanted to disable to windows firewall

	class { 'windows_firewall': ensure => 'stopped' }

## Allow port/protocol example ##
    windows_firewall::exception { 'WINRM':
      ensure       => present,
      direction    => 'in',
      action       => 'Allow',
      enabled      => 'yes',
      protocol     => 'TCP',
      port         => '5985',
      key_name     => 'WINRM-HTTP-In-TCP',
      display_name => 'Windows Remote Management HTTP-In',
      description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
    }

## Allow program example ##
   windows_firewall::exception { 'myapp':
     ensure       => present,
     direction    => 'in',
     action       => 'Allow',
     enabled      => 'yes',
     program      => 'C:\\myapp.exe',
     display_name => 'My App',
     description  => 'Inbound rule for My App',
   }

## Requirements ##

Tested against puppet versions 2.7.x and 3.x.x

These modules will also get installed as a dependency for this module:

* puppetlabs/stdlib
* joshcooper/powershell
* liamjbennett/win_facts

Please see the ModuleFile for further details.

