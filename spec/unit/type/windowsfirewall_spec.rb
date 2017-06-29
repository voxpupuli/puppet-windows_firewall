require 'spec_helper'

windowsfirewall = Puppet::Type.type(:windowsfirewall)

describe windowsfirewall do
  let :name do
    [ :domain, :public, :private, ]
  end

  context 'default_inbound_action property' do
    before do
      @provider = double 'provider'
      allow(@provider).to receive(:name).and_return(:ruby)
      windowsfirewall.stubs(:defaultprovider).returns @provider
      @default_inbound_action = windowsfirewall.new(name: 'customtype')
    end

  end
end
