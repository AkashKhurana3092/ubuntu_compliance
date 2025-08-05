# controls/package_test.rb

control 'package-01' do
  impact 1.0
  title 'Verify if curl is installed'
  desc 'Check if the curl package is installed on the system'

  describe package('curl') do
    it { should be_installed }
  end
end

# controls/user_test.rb

control 'user-01' do
  impact 1.0
  title 'Verify if ubuntu user exists'
  desc 'Ensure the user ubuntu is present on the system'

  describe user('courier_admin') do
    it { should exist }
  end


  describe user('inspec_admin') do
    it { should exist }
  end
end

# controls/user_test.rb

control 'package-02' do
  impact 1.0
  title 'Verify if ubuntu package exists'
  desc 'Ensure the user ubuntu is present on the system'

  describe package('xclip') do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_4.2.1.1.3_Ensure_systemd-journal-remote_is_enabled" do
  title "Ensure systemd-journal-remote is enabled"
  desc  "
    Journald (via systemd-journal-remote ) supports the ability to send log events it gathers to a remote log host or to receive messages from remote hosts, thus enabling centralised log management.
    
    Rationale: Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.
  "
  impact 0.0
  describe service("systemd-journal-upload") do
    it { should be_enabled }
  end
end