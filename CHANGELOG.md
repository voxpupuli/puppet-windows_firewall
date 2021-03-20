# Changelog

All notable changes to this project will be documented in this file.
Each new release typically also includes the latest modulesync defaults.
These should not affect the functionality of the module.

## [v4.0.0](https://github.com/voxpupuli/puppet-windows_firewall/tree/v4.0.0) (2021-03-20)

[Full Changelog](https://github.com/voxpupuli/puppet-windows_firewall/compare/v3.0.0...v4.0.0)

**Breaking changes:**

- Drop Puppet 5; require Puppet 6.1.0 [\#114](https://github.com/voxpupuli/puppet-windows_firewall/pull/114) ([bastelfreak](https://github.com/bastelfreak))

**Fixed bugs:**

- Fixing display\_name to default to the resource title [\#113](https://github.com/voxpupuli/puppet-windows_firewall/pull/113) ([msiroskey](https://github.com/msiroskey))
- Fix truncated verification [\#107](https://github.com/voxpupuli/puppet-windows_firewall/pull/107) ([JasonN3](https://github.com/JasonN3))

**Closed issues:**

- remote\_port and local\_port should also support string for comma-separated port list or dash-separated port range. [\#80](https://github.com/voxpupuli/puppet-windows_firewall/issues/80)

**Merged pull requests:**

- Local and Remote port range and csv \#80 [\#106](https://github.com/voxpupuli/puppet-windows_firewall/pull/106) ([sbezzy](https://github.com/sbezzy))
- Fixed provider for making changes via Puppet [\#104](https://github.com/voxpupuli/puppet-windows_firewall/pull/104) ([Nekototori](https://github.com/Nekototori))
- Make more use of data types [\#103](https://github.com/voxpupuli/puppet-windows_firewall/pull/103) ([alexjfisher](https://github.com/alexjfisher))

## [v3.0.0](https://github.com/voxpupuli/puppet-windows_firewall/tree/v3.0.0) (2020-07-30)

[Full Changelog](https://github.com/voxpupuli/puppet-windows_firewall/compare/v2.0.2...v3.0.0)

**Breaking changes:**

- modulesync 2.7.0 and drop puppet 4 [\#88](https://github.com/voxpupuli/puppet-windows_firewall/pull/88) ([bastelfreak](https://github.com/bastelfreak))

**Implemented enhancements:**

- New Provider with Types and Docs [\#89](https://github.com/voxpupuli/puppet-windows_firewall/pull/89) ([alexjfisher](https://github.com/alexjfisher))

**Fixed bugs:**

- Master O/S conditionals Completely Broken [\#66](https://github.com/voxpupuli/puppet-windows_firewall/issues/66)

**Closed issues:**

- Missing dependency puppetlabs-registry in PuppetForge version. [\#29](https://github.com/voxpupuli/puppet-windows_firewall/issues/29)

**Merged pull requests:**

- modulesync 3.0.0 & puppet-lint updates [\#101](https://github.com/voxpupuli/puppet-windows_firewall/pull/101) ([bastelfreak](https://github.com/bastelfreak))
- Bump puppetlabs/registry [\#99](https://github.com/voxpupuli/puppet-windows_firewall/pull/99) ([spotter-puppet](https://github.com/spotter-puppet))
- Allow puppetlabs/stdlib 6.x [\#98](https://github.com/voxpupuli/puppet-windows_firewall/pull/98) ([dhoppe](https://github.com/dhoppe))
- Remove duplicate CONTRIBUTING.md file [\#94](https://github.com/voxpupuli/puppet-windows_firewall/pull/94) ([dhoppe](https://github.com/dhoppe))
- Support puppetlabs/stdlib 6.x. [\#92](https://github.com/voxpupuli/puppet-windows_firewall/pull/92) ([pillarsdotnet](https://github.com/pillarsdotnet))
- removed operatingsystemversion and old os testing [\#90](https://github.com/voxpupuli/puppet-windows_firewall/pull/90) ([Nekototori](https://github.com/Nekototori))
- Remove Linux acceptance nodesets [\#84](https://github.com/voxpupuli/puppet-windows_firewall/pull/84) ([ekohl](https://github.com/ekohl))

## [v2.0.2](https://github.com/voxpupuli/puppet-windows_firewall/tree/v2.0.2) (2018-10-19)

[Full Changelog](https://github.com/voxpupuli/puppet-windows_firewall/compare/v2.0.1...v2.0.2)

**Fixed bugs:**

- Documentation is not updated for new puppet 4 data types [\#65](https://github.com/voxpupuli/puppet-windows_firewall/issues/65)

**Closed issues:**

- Update documentation for changed attribute data types [\#79](https://github.com/voxpupuli/puppet-windows_firewall/issues/79)

**Merged pull requests:**

- modulesync 2.2.0 and allow puppet 6.x [\#82](https://github.com/voxpupuli/puppet-windows_firewall/pull/82) ([bastelfreak](https://github.com/bastelfreak))
- example and param doc update [\#81](https://github.com/voxpupuli/puppet-windows_firewall/pull/81) ([joeypiccola](https://github.com/joeypiccola))
- allow puppetlabs/stdlib 5.x [\#77](https://github.com/voxpupuli/puppet-windows_firewall/pull/77) ([bastelfreak](https://github.com/bastelfreak))

## [v2.0.1](https://github.com/voxpupuli/puppet-windows_firewall/tree/v2.0.1) (2018-08-20)

[Full Changelog](https://github.com/voxpupuli/puppet-windows_firewall/compare/v2.0.0...v2.0.1)

**Fixed bugs:**

- Remove hardcoded c drive reference for firewall exceptions [\#63](https://github.com/voxpupuli/puppet-windows_firewall/pull/63) ([TraGicCode](https://github.com/TraGicCode))

**Closed issues:**

- Update puppetlabs-registry module dependency [\#72](https://github.com/voxpupuli/puppet-windows_firewall/issues/72)
- Don't  working when Windows installed not on drive C:\ [\#52](https://github.com/voxpupuli/puppet-windows_firewall/issues/52)
- Use in-built Windows Facter facts [\#45](https://github.com/voxpupuli/puppet-windows_firewall/issues/45)
- liamjbennett/win\_facts module causes Registry errors [\#34](https://github.com/voxpupuli/puppet-windows_firewall/issues/34)
- fixing remote ports [\#22](https://github.com/voxpupuli/puppet-windows_firewall/issues/22)
- fix broken ensure=absent [\#21](https://github.com/voxpupuli/puppet-windows_firewall/issues/21)

**Merged pull requests:**

- allow puppetlabs/registry 2.x [\#74](https://github.com/voxpupuli/puppet-windows_firewall/pull/74) ([bastelfreak](https://github.com/bastelfreak))
- Remove docker nodesets [\#69](https://github.com/voxpupuli/puppet-windows_firewall/pull/69) ([bastelfreak](https://github.com/bastelfreak))
- drop EOL OSs; fix puppet version range [\#68](https://github.com/voxpupuli/puppet-windows_firewall/pull/68) ([bastelfreak](https://github.com/bastelfreak))
- Puppet 4+ data types to get rid of some validate\_re [\#61](https://github.com/voxpupuli/puppet-windows_firewall/pull/61) ([ofalk](https://github.com/ofalk))

## [v2.0.0](https://github.com/voxpupuli/puppet-windows_firewall/tree/v2.0.0) (2017-11-17)

[Full Changelog](https://github.com/voxpupuli/puppet-windows_firewall/compare/v1.1.0...v2.0.0)

**Merged pull requests:**

- bump puppet version dependency to \>= 4.7.1 \< 6.0.0 [\#58](https://github.com/voxpupuli/puppet-windows_firewall/pull/58) ([bastelfreak](https://github.com/bastelfreak))

## [v1.1.0](https://github.com/voxpupuli/puppet-windows_firewall/tree/v1.1.0) (2017-02-11)

This is the last release with Puppet3 support!
* Fix several markdown issues
* Add missing badges
* Fix several rubocop issues
* Set min version_requirement for Puppet + bump deps
* Rubocop: automatic fixes

## 2016-05-08 Release 1.0.3

* modulesync with voxpupuli defaults

## 2016-02-03 Release 1.0.2

* Added support for matching remote ports


## 2015-07-23 Release 1.0.1

* Fixed rules not being deleted


## 2013-10-20 Release 0.0.3

* Add program rule support, various other fixes


## 2013-10-20 Release 0.0.2

* Some bug fixes and additional testing


## 2013-10-20 Release 0.0.1

* The initial version


\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
