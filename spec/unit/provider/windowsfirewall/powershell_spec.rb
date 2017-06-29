require 'spec_helper'
provider_resource = Puppet::Type.type(:windowsfirewall)
provider_class = provider_resource.provider(:powershell)

describe provider_class do
  context 'operating system confine' do
    subject do
      provider_class.confine_collection.summary[:variable][:operatingsystem]
    end
    it { is_expected.to eq ['windows'] }
  end
end

