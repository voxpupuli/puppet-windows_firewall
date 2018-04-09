Puppet::Type.newtype(:windowsfirewall) do
  desc 'Puppet type that models Windows Firewall rules'
  ensurable

  newparam(:name, namevar: true) do
    newvalues(:domain, :public, :private)
    desc "Windows firewall zones - either 'domain', 'public', or 'private'"
    munge(&:downcase)
  end

  newproperty(:default_inbound_action) do
    desc 'Default inbound rules for the zone'
    munge(&:capitalize)
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:default_outbound_action) do
    desc 'Default outbound rules for the zone'
    munge(&:capitalize)
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:allow_inbound_rules) do
    desc 'Allow inbound rules'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:allow_local_firewall_rules) do
    desc 'Allow local firewall rules'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:allow_local_ipsec_rules) do
    desc 'Allow local IPsec rules'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:allow_user_apps) do
    desc 'Allow user apps'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:allow_user_ports) do
    desc 'Allow user ports'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:allow_unicast_response_to_multicast) do
    desc 'Allow unicast response to multicast'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:notify_on_listen) do
    desc 'Notify on listen'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:enable_stealth_mode_for_ipsec) do
    desc 'Enable stealth mode for IPsec'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:log_file_name) do
    desc 'Log file name'
    munge(&:downcase)
    def insync?(is)
      is.casecmp(should.downcase).zero?
    end
  end

  newproperty(:log_max_size_kilobytes) do
    desc 'Log max size - in kilobytes'
    munge do |value|
      Integer(value)
    end
    def insync?(is)
      Integer(is) == Integer(should)
    end
  end

  newproperty(:log_allowed) do
    desc 'Log allowed'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:log_blocked) do
    desc 'Log blocked'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:log_ignored) do
    desc 'Log ignored'
    munge do |value|
      value.to_s.capitalize
    end
    def insync?(is)
      is.capitalize == should.capitalize
    end
  end

  newproperty(:disabled_interface_aliases) do
    desc 'Disabled interface aliases'
    munge(&:downcase)
    def insync?(is)
      is.casecmp(should.downcase).zero?
    end
  end
end
