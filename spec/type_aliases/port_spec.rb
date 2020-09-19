require 'spec_helper'

describe 'Windows_firewall::Port' do
  it { is_expected.to allow_value('1') }
  it { is_expected.to allow_value('12') }
  it { is_expected.to allow_value('20343') }
  it { is_expected.to allow_value('5089-5196') }
  it { is_expected.to allow_value('5089,5091,5093') }
  it { is_expected.to allow_value('any') }

  it { is_expected.not_to allow_value('') }
  it { is_expected.not_to allow_value('6534*') }
end
