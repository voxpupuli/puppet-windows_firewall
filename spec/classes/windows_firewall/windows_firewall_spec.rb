require 'spec_helper'

describe 'windows_firewall', type: :class do
  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "with OS: #{os}, ensure: running" do
      let :facts do
        { operatingsystemversion: os }
      end
      let :params do
        { ensure: 'running' }
      end

      it do
        is_expected.to contain_service('windows_firewall').with(
          'name'   => 'SharedAccess',
          'ensure' => 'running',
          'enable' => 'true'
        )
      end

      it do
        is_expected.to contain_registry_value('EnableFirewallDomainProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall',
          'data'   => '1'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallPublicProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall',
          'data'   => '1'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallStandardProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall',
          'data'   => '1'
        )
      end
    end
  end

  ['Windows 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "with OS: #{os}, ensure: running" do
      let :facts do
        { operatingsystemversion: os }
      end
      let :params do
        { ensure: 'running' }
      end

      it do
        is_expected.to contain_service('windows_firewall').with(
          'name'   => 'MpsSvc',
          'ensure' => 'running',
          'enable' => 'true'
        )
      end

      it do
        is_expected.to contain_registry_value('EnableFirewallDomainProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall',
          'data'   => '1'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallPublicProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall',
          'data'   => '1'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallStandardProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall',
          'data'   => '1'
        )
      end
    end
  end

  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "with OS: #{os}, ensure: stopped" do
      let :facts do
        { operatingsystemversion: os }
      end
      let :params do
        { ensure: 'stopped' }
      end

      it do
        is_expected.to contain_service('windows_firewall').with(
          'name'   => 'SharedAccess',
          'ensure' => 'stopped',
          'enable' => 'false'
        )
      end

      it do
        is_expected.to contain_registry_value('EnableFirewallDomainProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall',
          'data'   => '0'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallPublicProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall',
          'data'   => '0'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallStandardProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall',
          'data'   => '0'
        )
      end
    end
  end

  ['Windows 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "with OS: #{os}, ensure: stopped" do
      let :facts do
        { operatingsystemversion: os }
      end
      let :params do
        { ensure: 'stopped' }
      end

      it do
        is_expected.to contain_service('windows_firewall').with(
          'name'   => 'MpsSvc',
          'ensure' => 'stopped',
          'enable' => 'false'
        )
      end

      it do
        is_expected.to contain_registry_value('EnableFirewallDomainProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall',
          'data'   => '0'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallPublicProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall',
          'data'   => '0'
        )
      end
      it do
        is_expected.to contain_registry_value('EnableFirewallStandardProfile').with(
          'ensure' => 'present',
          'path'   => '32:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall',
          'data'   => '0'
        )
      end
    end
  end

  context 'passing invalid type for param ensure' do
    let :params do
      { ensure: %w[not a string] }
    end

    it do
      expect do
        is_expected.to contain_registry_value('EnableFirewall')
      end.to raise_error(Puppet::Error, %r{expects a String value})
    end
  end
end
