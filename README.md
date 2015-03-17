# windows_firewall

####Table of Contents

1. [Overview - What is the windows_firewall module?](#overview)
2. [Module Description - What does the module do?](#module-description)
3. [Setup - The basics of getting started with windows_firewall](#setup)
    * [Beginning with windows_firewall - Installation](#beginning-with-windows_firewall)
    * [Configuring an exception - Basic options for for getting started](#configure-an-exception)
4. [Usage - The classes, defined types, and their parameters available for configuration](#usage)
    * [Classes and Defined Types](#classes-and-defined-types)
        * [Class: windows_firewall](#class-windows_firewall)
        * [Defined Type: windows_firewall::exception](#defined-type-exception)
5. [Implementation - An under-the-hood peek at what the module is doing](#implementation)
    * [Classes and Defined Types](#classes-and-defined-types)
    * [Templates](#templates)
6. [Limitations - OS compatibility, etc.](#limitations)
7. [Development - Guide for contributing to the module](#development)
8. [Release Notes - Notes on the most recent updates to the module](#release-notes)

##Overview
This is a module that will manage the Microsoft Windows Firewall and it's exceptions.

[![Build Status](https://secure.travis-ci.org/puppet-community/puppet-windows_firewall.png)](http://travis-ci.org/puppet-community/puppet-windows_firewall)

##Module Description

The windows_firewall module will primarily manage the state of the windows firewall application on your windows system. Optionally it will also
allow you to configure any exceptions that you need to have in place.

##Setup

###What windows_firewall affects:

* windows firewall service and corrisponding Windows Registry keys
* windows registry keys and values for any defined exception rules

###Beginning with windows_firewall

The windows_firewall resource allows you to manage the firewall service itself.

	class { 'windows_firewall': ensure => 'stopped' }

Once the windows firewall is managed you may then want to start managing the rules and exceptions within it.

    windows_firewall::exception { 'WINRM':
      ensure       => present,
      direction    => 'in',
      action       => 'Allow',
      enabled      => 'yes',
      protocol     => 'TCP',
      local_port   => '5985',
      display_name => 'Windows Remote Management HTTP-In',
      description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
    }

##Usage

###Classes and Defined Types:

####Class: `windows_firewall`

**Parameters within `windows_firewall`:**

#####`ensure`
Determines whether or not the service must be running and enabled. If not included, the module will assume that the windows firewall service should be running and enabled. Valid values are 'running' and 'stopped'.

###Defined Type: `windows_firewall::exception`

**Parameters within `windows_firewall::exception`:**

#####`ensure`
Determines whether or not the firewall exception is 'present' or 'absent'

#####`direction`
Sets the direction of the exception rule, either: 'in' or 'out'.

#####`action`
Sets the action type of the excepton, either: 'allow' or 'block'.

#####`enabled`
Determines whether the exception is enabled, either: 'yes' or 'no'. Defaults to 'yes'.

#####`protocol`
Sets the protocol to be included in the exception rule, either: 'TCP' or 'UDP'.

#####`local_port`
Defines the port to be included in the exception for port-based exception rules.

#####`remote_ip`
Specifies remote hosts that can use this rule.

#####`program`
Defines the full path to the program to be included in the exception for program-based exception rules

#####`display_name`
Sets the Display Name of the exception rule. Defaults to the title of the resource.

#####`description`
A description of the exception to apply.

#####`allow_edge_traversal`
Specifies that the traffic for this exception traverses an edge device

##Reference

###Classes
####Public Classes
* [`windows_firewall`](#class-windows_firewall): The main class of the module for managing the state of the windows firewall.

###Defined Types
####Public Types:
* [`windows_firewall::exception`] Manages the configuration of firewall exceptions

##Limitations

This module is tested on the following platforms:

* Windows 2008 R2

It is tested with the OSS version of Puppet only.

##Development

###Contributing

Please read CONTRIBUTING.md for full details on contributing to this project.
