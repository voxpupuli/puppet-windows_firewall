Puppet module for managing the [Windows Firewall]().

This module is also available on the [Puppet Forge](https://forge.puppetlabs.com/liamjbennett/windows_firewall)

[![Build
Status](https://secure.travis-ci.org/liamjbennett/puppet-windows_firewall.png)](http://travis-ci.org/liamjbennett/puppet-windows_firewall)
[![Dependency
Status](https://gemnasium.com/liamjbennett/puppet-windows_firewall.png)](http://gemnasium.com/liamjbennett/puppet-windows_firewall)

## Configuration ##
The windows_firewall class has some defaults that can be overridden, for instance if you wanted to disable to windows firewall

	class { 'windows_firewall': ensure => 'stopped' }

## Requirements ##

Tested against puppet versions 2.7.x and 3.x.x

These modules will also get installed as a dependency for this module:

puppetlabs/stdlib
joshcooper/powershell
liamjbennett/win_facts

Please see the ModuleFile for further details.

