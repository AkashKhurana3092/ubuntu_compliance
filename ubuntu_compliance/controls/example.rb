# controls/package_test.rb

control 'package-01' do
  impact 1.0
  title 'Verify if curl is installed'
  desc 'Check if the curl package is installed on the system'

  describe package('curl') do
    it { should be_installed }
  end
end



