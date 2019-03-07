require 'spec_helper'

describe 'windows_firewall::exception', type: :define do
  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "port rule with OS: #{os}, ensure: present" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe firewall add portopening name="Windows Remote Management" mode=ENABLE protocol=TCP port="5985"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "port rule with OS: #{os}, ensure: present" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985, remote_port: 'any',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe advfirewall firewall add rule name="Windows Remote Management" description="Inbound rule for WinRM" dir=in action=allow enable=yes edge=no protocol=TCP localport="5985" remoteport="any" remoteip="" profile="Any"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "program rule with OS: #{os}, ensure: present" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow',
          enabled: true, program: 'C:\\foo.exe',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe firewall add allowedprogram name="Windows Remote Management" mode=ENABLE program="C:\\foo.exe"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "program rule with OS: #{os}, ensure: present" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow',
          enabled: true, program: 'C:\\foo.exe',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe advfirewall firewall add rule name="Windows Remote Management" description="Inbound rule for WinRM" dir=in action=allow enable=yes edge=no program="C:\\foo.exe" remoteip="" profile="Any"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "port rule with OS: #{os}, ensure: absent" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'absent', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe firewall delete portopening name="Windows Remote Management" mode=ENABLE protocol=TCP port="5985"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "port rule with OS: #{os}, ensure: absent" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'absent', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985, remote_port: 'any',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe advfirewall firewall delete rule name="Windows Remote Management"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "program rule with OS: #{os}, ensure: absent" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'absent', direction: 'in', action: 'allow',
          enabled: true, program: 'C:\\foo.exe',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe firewall delete allowedprogram name="Windows Remote Management" mode=ENABLE program="C:\\foo.exe"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "program rule with OS: #{os}, ensure: absent" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'absent', direction: 'in', action: 'allow',
          enabled: true, program: 'C:\\foo.exe',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe advfirewall firewall delete rule name="Windows Remote Management"',
          'provider' => 'windows'
        )
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Server 2003 R2', 'Windows Server 2003', 'Windows 8', 'Windows 7', 'Windows Vista', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, ensure => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'invalid', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error)
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Server 2003 R2', 'Windows Server 2003', 'Windows 8', 'Windows 7', 'Windows Vista', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, display_name => >255" do
      long_display_name =
        'kbqsCQPnQKYPOWEUItAj72ldtdGqBBK1etCZycAVsuNNY8fNCF4av4yaDppQ1upex5moV5RHd88rHdG5DegNEYR2b7DI3thTewgP
        1RTgW7xawfeDOZOZh2CbmV7zPOqbF8rXxFwxtugUBIpxmpQ8TCk93wF04RicJidwhhiKQz5YXwTbMbREXtQz25mhkPxOI6cyA9QJ
        kQmssLmRxKxxtQ1YKithCfinHOQeDpDXxAtcRsHyKCjjDTt8bZREKexMxx2t'

      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }

      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: long_display_name, description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error)
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Server 2003 R2', 'Windows Server 2003', 'Windows 8', 'Windows 7', 'Windows Vista', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, enabled => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: 'invalid',
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error)
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Server 2003 R2', 'Windows Server 2003', 'Windows 8', 'Windows 7', 'Windows Vista', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, protocol => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'invalid', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error)
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows Server 2003 R2', 'Windows Server 2003', 'Windows 8', 'Windows 7', 'Windows Vista', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, local_port => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 'invalid',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error)
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "with invalid custom param: os => #{os}, description => >255" do
      long_description =
        'kbqsCQPnQKYPOWEUItAj72ldtdGqBBK1etCZycAVsuNNY8fNCF4av4yaDppQ1upex5moV5RHd88rHdG5DegNEYR2b7DI3thTewgP
        1RTgW7xawfeDOZOZh2CbmV7zPOqbF8rXxFwxtugUBIpxmpQ8TCk93wF04RicJidwhhiKQz5YXwTbMbREXtQz25mhkPxOI6cyA9QJ
        kQmssLmRxKxxtQ1YKithCfinHOQeDpDXxAtcRsHyKCjjDTt8bZREKexMxx2t'

      let :facts do
        {
          operatingsystemversion: 'Windows Server 2008 R2',
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }

      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: long_description
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error)
      end
    end
  end

  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, description => >255" do
      long_description =
        'kbqsCQPnQKYPOWEUItAj72ldtdGqBBK1etCZycAVsuNNY8fNCF4av4yaDppQ1upex5moV5RHd88rHdG5DegNEYR2b7DI3thTewgP
        1RTgW7xawfeDOZOZh2CbmV7zPOqbF8rXxFwxtugUBIpxmpQ8TCk93wF04RicJidwhhiKQz5YXwTbMbREXtQz25mhkPxOI6cyA9QJ
        kQmssLmRxKxxtQ1YKithCfinHOQeDpDXxAtcRsHyKCjjDTt8bZREKexMxx2t'

      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }

      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: long_description
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.not_to raise_error
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "with invalid custom param: os => #{os}, direction => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'invalid', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error)
      end
    end
  end

  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, direction => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'invalid', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error, %r{expects a match for Enum})
      end
    end
  end

  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "with invalid custom param: os => #{os}, action => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'invalid', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error, %r{expects a match for Enum})
      end
    end
  end

  ['Windows Server 2003', 'Windows Server 2003 R2', 'Windows XP'].each do |os|
    context "with invalid custom param: os => #{os}, action => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'invalid', enabled: true,
          protocol: 'TCP', local_port: 5985,
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error, %r{expects a match for Enum})
      end
    end
  end
  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "port rule with OS: #{os}, ensure: present" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: '1000-2000,2048', remote_port: 'any',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe advfirewall firewall add rule name="Windows Remote Management" description="Inbound rule for WinRM" dir=in action=allow enable=yes edge=no protocol=TCP localport="1000-2000,2048" remoteport="any" remoteip="" profile="Any"',
          'provider' => 'windows'
        )
      end
    end
  end
  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "port rule with OS: #{os}, ensure: present" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'TCP', local_port: 'RPC', remote_port: 'any',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        is_expected.to contain_exec('set rule Windows Remote Management').with(
          'command' => 'C:\\windows\\system32\\netsh.exe advfirewall firewall add rule name="Windows Remote Management" description="Inbound rule for WinRM" dir=in action=allow enable=yes edge=no protocol=TCP localport="RPC" remoteport="any" remoteip="" profile="Any"',
          'provider' => 'windows'
        )
      end
    end
  end
  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "with invalid custom param: os => #{os}, action => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'UDP', local_port: 'RPC',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error, %r{RPC and RPC-EPMap local ports require TCP})
      end
    end
  end
  ['Windows Server 2012', 'Windows Server 2008', 'Windows Server 2008 R2', 'Windows 8', 'Windows 7', 'Windows Vista'].each do |os|
    context "with invalid custom param: os => #{os}, action => invalid" do
      let :facts do
        {
          operatingsystemversion: os,
          os: {
            windows: {
              system32: 'C:\\windows\\system32'
            }
          }
        }
      end
      let(:title) { 'Windows Remote Management' }
      let :params do
        {
          ensure: 'present', direction: 'in', action: 'allow', enabled: true,
          protocol: 'ICMPv4', local_port: 'RPC',
          display_name: 'Windows Remote Management', description: 'Inbound rule for WinRM'
        }
      end

      it do
        expect do
          is_expected.to contain_exec('set rule Windows Remote Management')
        end.to raise_error(Puppet::Error, %r{local and/or remote ports are not needed when protocol is ICMP})
      end
    end
  end
end
