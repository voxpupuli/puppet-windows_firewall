# Windows Firewall module for Puppet

[![Build Status](https://travis-ci.org/voxpupuli/puppet-windows_firewall.png?branch=master)](https://travis-ci.org/voxpupuli/puppet-windows_firewall)
[![Code Coverage](https://coveralls.io/repos/github/voxpupuli/puppet-windows_firewall/badge.svg?branch=master)](https://coveralls.io/github/voxpupuli/puppet-windows_firewall)
[![Puppet Forge](https://img.shields.io/puppetforge/v/puppet/windows_firewall.svg)](https://forge.puppetlabs.com/puppet/windows_firewall)
[![Puppet Forge - downloads](https://img.shields.io/puppetforge/dt/puppet/windows_firewall.svg)](https://forge.puppetlabs.com/puppet/windows_firewall)
[![Puppet Forge - endorsement](https://img.shields.io/puppetforge/e/puppet/windows_firewall.svg)](https://forge.puppetlabs.com/puppet/windows_firewall)
[![Puppet Forge - scores](https://img.shields.io/puppetforge/f/puppet/windows_firewall.svg)](https://forge.puppetlabs.com/puppet/windows_firewall)

#### Table of Contents

1. [Overview - What is the windows_firewall module?](#overview)
1. [Module Description - What does the module do?](#module-description)
1. [Setup - The basics of getting started with windows_firewall](#setup)
    * [Beginning with windows_firewall - Installation](#beginning-with-windows_firewall)
    * [Configuring an exception - Basic options for for getting started](#configure-an-exception)
1. [Usage - The classes, defined types, and their parameters available for configuration](#usage)
    * [Classes and Defined Types](#classes-and-defined-types)
        * [Class: windows_firewall](#class-windows_firewall)
        * [Defined Type: windows_firewall::exception](#defined-type-exception)
1. [Implementation - An under-the-hood peek at what the module is doing](#implementation)
    * [Classes and Defined Types](#classes-and-defined-types)
    * [Templates](#templates)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)
1. [Release Notes - Notes on the most recent updates to the module](#release-notes)

## Overview

This is a module that will manage the Microsoft Windows Firewall and it's exceptions.

## Module Description

The windows_firewall module will primarily manage the state of the windows firewall
application on your windows system. Optionally it will also allow you to configure
any exceptions that you need to have in place.

## Setup

### What windows_firewall affects

* windows firewall service and corresponding Windows Registry keys
* windows registry keys and values for any defined exception rules

### Beginning with windows_firewall

The windows_firewall resource allows you to manage the firewall service itself.

```
class { 'windows_firewall': ensure => 'stopped' }
```

On Server 2012 and up, additional features are available to be managed,
including Windows firewall zones Domain, Public, and Private via types
and providers.

```
class { 'windows_firewall':
  ensure => 'running',
}
windowsfirewall { 'domain':
  ensure                              => 'present',
  default_outbound_action             => 'allow',
}
```

You may also query resources on Server 2012 and up via `puppet resource
windowsfirewall`.

Once the windows firewall is managed you may then want to start managing the rules
and exceptions within it.

```
windows_firewall::exception { 'WINRM':
  ensure       => present,
  direction    => 'in',
  action       => 'allow',
  enabled      => true,
  protocol     => 'TCP',
  local_port   => 5985,
  remote_port  => 'any',
  display_name => 'Windows Remote Management HTTP-In',
  description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
}
```

## Usage

### Classes and Defined Types

#### Class: `windows_firewall`

**Parameters within `windows_firewall`:**

##### `ensure`

Determines whether or not the service must be running and enabled. If not
included, the module will assume that the windows firewall service should be
running and enabled. Valid values are 'running' and 'stopped'.

#### Defined Type: `windows_firewall::exception`

**Parameters within `windows_firewall::exception`:**

##### `ensure`

Determines whether or not the firewall exception is 'present' or 'absent'

##### `direction`

Sets the direction of the exception rule, either: 'in' or 'out'.

##### `action`

Sets the action type of the exception, either: 'allow' or 'block'.

##### `enabled`

Determines whether the exception is enabled, either: 'true' or 'false'. Defaults to 'true'.

##### `protocol`

Sets the protocol to be included in the exception rule, either: 'TCP' or 'UDP'.

##### `local_port`

Defines the local port to be included in the exception for port-based exception
rules, either: an integer between 1 and 65535, a port range (two integers separated by a hyphen, a comma separated list of integers, or the string 'any'.

##### `remote_port`

Defines the remote port to be included in the exception for port-based exception
rules, either: an integer between 1 and 65535, a port range (two integers separated by a hyphen, a comma separated list of integers, or the string 'any'.

##### `remote_ip`

Specifies remote hosts that can use this rule.

##### `program`

Defines the full path to the program to be included in the exception for
program-based exception rules

##### `display_name`

Sets the Display Name of the exception rule. Defaults to the title of the resource.

##### `description`

A description of the exception to apply.

##### `allow_edge_traversal`

Specifies that the traffic for this exception traverses an edge device

**Parameters within `windowsfirewall` (Limited to 2012 and up)**

##### `ensure`

Determines whether the firewall zone is Enabled, 'present', or Disabled,
'absent'.

##### `allow_inbound_rules`

Specifies whether the firewall blocks inbound traffic or not. If set to
'False', then all inbound firewall rules will be ignored. Accepts
'True', 'False', or 'NotConfigured'. Defaults to 'NotConfigured'.

##### `allow_local_firewall_rules`

Specifies whether the local firewall rules should be merged into the
effective policy along with Group Policy settings. If set to 'False',
then all rules defined by the local administrator are ignored, and only
GPO based firewall rules are applied. Accepts 'True', 'False', or
'NotConfigured'. Defaults to 'NotConfigured'.

##### `allow_local_ipsec_rules`

Specifies whether the local IPsec rules should be merged into the
effective policy along with Group Policy settings. If set to 'False',
then all rules defined by the local administrator are ignored, and only
GPO based IPsec rules are applied. Accepts 'True', 'False', or
'NotConfigured'. Defaults to 'NotConfigured'.

##### `allow_unicast_response_to_multicast`

Allows unicast responses to multi-cast traffic.  If set to 'False', the
computer discards unicast responses to outgoing multi-cast or broadcast
messages. Accepts 'True', 'False', or 'NotConfigured'. Defaults to
'NotConfigured'.

##### `allow_user_apps`

Specifies whether traffic from local user applications is allowed
through the firewall. Accepts 'True', 'False', or 'NotConfigured'.
Defaults to 'NotConfigured'.

##### `allow_user_ports`

Specifies whether traffic is allowed through local user ports. Accepts
'True', 'False', or 'NotConfigured'. Defaults to 'NotConfigured'.

##### `default_inbound_action`

Specifies how to filter inbound traffic. 'Allow' allows all inbound
network traffic, whether or not it matches an inbound rule. Accepts
'Block', 'Allow', or 'NotConfigured'. Defaults to 'Block'.

##### `default_outbound_action`

Specifies how to filter outbound traffic. 'Block' blocks outbound
network traffic that does not match an outbound rule. Accepts 'Block',
'Allow', or 'NotConfigured'.  Defaults to 'Allow'.

##### `disabled_interface_aliases`

Specifies a list of interfaces on which firewall settings are excluded.

##### `enable_stealth_mode_for_ipsec`

Enables stealth mode for IPsec traffic. If set to 'True', it will block
outgoing ICMP unreachable and TCP reset messages for a port when no
application is listening on that port. Accepts 'True', 'False', or
'NotConfigured'. Defaults to 'NotConfigured'.

##### `log_allowed`

Specifies how to handle logging for allowed packets. If set to 'True',
Windows writes an entry to the log whenever an incoming or outgoing
connection is allowed by the policy. Accepts 'True', 'False', or
'NotConfigured'. Defaults to 'False'.

##### `log_blocked`

Specifies how to handle logging for dropped packets. If set to 'True',
Windows writes an entry to the log whenever an incoming or outgoing
connection is prevented by the policy. Accepts 'True', 'False', or
'NotConfigured'. Defaults to 'False'.

##### `log_ignored`

Specifies how to handle logging for ignored packets. If set to 'True',
windows writes an entry to the log whenever an incoming or outgoing
connection is prevented by the policy. Accepts 'True', 'False', or
'NotConfigured'. Defaults to 'False'.

##### `log_file_name`

Specifies the path and filename of the file to which log entries are
written. Accepts windows environment variables.  Defaults to
`%windir%\system32\logfiles\firewall\pfirewall.log`.

##### `log_max_size_kilobytes`

Specifies the maximum file size of the log. Accepts a number between '1'
and '32767'. Defaults to '4096'.

##### `notify_on_listen`

Specifies whether user gets notified when an application starts
listening for inbound connections. If set to 'False', Windows does not
notify the user whenever a program or service starts listening for
inbound connections. Accepts 'True', 'False', or 'NotConfigured'.
Defaults to 'True'.

## Reference

### Classes

#### Public Classes

* [`windows_firewall`](#class-windows_firewall): The main class of the module for
  managing the state of the windows firewall.

### Defined Types

#### Public Types

* [`windows_firewall::exception`] Manages the configuration of firewall exceptions

### Module Specific Provider

* [`windowsfirewall`] Manages the configuration of firewall zones.

## Limitations

This module is tested on the following platforms:

* Windows 2008 R2, Windows 2012 R2, and Windows 2016.

## Development

### Contributing

Please read CONTRIBUTING.md for full details on contributing to this project.
