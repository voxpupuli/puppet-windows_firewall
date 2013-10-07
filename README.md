#Windows Firewall module for Puppet

#Overview
Puppet module to manage the Microsoft Windows Firewall

This module is also available on the [Puppet Forge](https://forge.puppetlabs.com/liamjbennett/windows_firewall)

[![Build
Status](https://secure.travis-ci.org/liamjbennett/puppet-windows_firewall.png)](http://travis-ci.org/liamjbennett/puppet-windows_firewall)
[![Dependency
Status](https://gemnasium.com/liamjbennett/puppet-windows_firewall.png)](http://gemnasium.com/liamjbennett/puppet-windows_firewall)

##Module Description

##Setup

####Setup Requirements



##Usage
First please read the [Wiki](https://github.com/liamjbennett/puppet-windows_firewall/wiki) regarding how we assume your network
share should be configured. Then installing office is as simple as:

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

##Development
Copyright (C) 2013 Liam Bennett - <liamjbennett@gmail.com> <br/>
Distributed under the terms of the Apache 2 license - see LICENSE file for details. <br/>
Further contributions and testing reports are extremely welcome - please submit a pull request or issue on [GitHub](https://github.com/liamjbennett/puppet-windows_firewall) <br/>
Please read the [Wiki](https://github.com/liamjbennett/puppet-windows_firewall/wiki) as there is a lot of useful information and links that will help you understand this module <br/>

##Release Notes
__0.0.3__ <br/>
Add program rule support, various other fixes

__0.0.2__ <br/>
Some bug fixes and additional testing

__0.0.1__ <br/>
The initial version
