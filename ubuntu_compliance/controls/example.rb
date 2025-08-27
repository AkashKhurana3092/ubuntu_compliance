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

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled" do
  title "Ensure mounting of cramfs filesystems is disabled"
  desc  "
    The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.
    
    Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  impact 1.0
  describe kernel_module('cramfs') do
    it { should_not be_loaded }
    it { should be_disabled }
    it { should be_blacklisted }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2.1_Ensure_tmp_is_a_separate_partition" do
  title "Ensure /tmp is a separate partition"
  desc  "
    The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.
    
    Rationale: Making /tmp its own file system allows an administrator to set additional mount options such as the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to a system setuid program and wait for it to be updated. Once the program was updated, the hard link would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.
    
    This can be accomplished by either mounting tmpfs to /tmp , or creating a separate partition for /tmp .
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe command("systemctl is-enabled tmp.mount").stdout do
    it { should match(/(?i)^(generated|enabled)$/)}
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2.2_Ensure_nodev_option_set_on_tmp_partition" do
  title "Ensure nodev option set on /tmp partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /tmp .
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2.3_Ensure_noexec_option_set_on_tmp_partition" do
  title "Ensure noexec option set on /tmp partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp .
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2.4_Ensure_nosuid_option_set_on_tmp_partition" do
  title "Ensure nosuid option set on /tmp partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /tmp .
  "
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.3.2_Ensure_nodev_option_set_on_var_partition" do
  title "Ensure nodev option set on /var partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /var filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var .
  "
  impact 1.0
  describe mount("/var") do
    it { should be_mounted }
  end
  describe mount("/var") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.3.3_Ensure_nosuid_option_set_on_var_partition" do
  title "Ensure nosuid option set on /var partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Since the /var filesystem is only intended for variable files such as logs, set this option to ensure that users cannot create setuid files in /var .
  "
  impact 1.0
  describe mount("/var") do
    it { should be_mounted }
  end
  describe mount("/var") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4.2_Ensure_noexec_option_set_on_vartmp_partition" do
  title "Ensure noexec option set on /var/tmp partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp .
  "
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4.3_Ensure_nosuid_option_set_on_vartmp_partition" do
  title "Ensure nosuid option set on /var/tmp partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp .
  "
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4.4_Ensure_nodev_option_set_on_vartmp_partition" do
  title "Ensure nodev option set on /var/tmp partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var/tmp .
  "
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5.2_Ensure_nodev_option_set_on_varlog_partition" do
  title "Ensure nodev option set on /var/log partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /var/log filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var/log .
  "
  impact 1.0
  describe mount("/var/log") do
    it { should be_mounted }
  end
  describe mount("/var/log") do
    its("options") { should include "nodev" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5.3_Ensure_noexec_option_set_on_varlog_partition" do
  title "Ensure noexec option set on /var/log partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Since the /var/log filesystem is only intended for log files, set this option to ensure that users cannot run executable binaries from /var/log .
  "
  impact 1.0
  describe mount("/var/log") do
    it { should be_mounted }
  end
  describe mount("/var/log") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5.4_Ensure_nosuid_option_set_on_varlog_partition" do
  title "Ensure nosuid option set on /var/log partition"
  desc  "
    The nosuid mount option specifies that the filesystem cannot contain setuid files.
    
    Rationale: Since the /var/log filesystem is only intended for log files, set this option to ensure that users cannot create setuid files in /var/log .
  "
  impact 1.0
  describe mount("/var/log") do
    it { should be_mounted }
  end
  describe mount("/var/log") do
    its("options") { should include "nosuid" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.6.2_Ensure_noexec_option_set_on_varlogaudit_partition" do
  title "Ensure noexec option set on /var/log/audit partition"
  desc  "
    The noexec mount option specifies that the filesystem cannot contain executable binaries.
    
    Rationale: Since the /var/log/audit filesystem is only intended for audit logs, set this option to ensure that users cannot run executable binaries from /var/log/audit .
  "
  impact 1.0
  describe mount("/var/log/audit") do
    it { should be_mounted }
  end
  describe mount("/var/log/audit") do
    its("options") { should include "noexec" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.6.3_Ensure_nodev_option_set_on_varlogaudit_partition" do
  title "Ensure nodev option set on /var/log/audit partition"
  desc  "
    The nodev mount option specifies that the filesystem cannot contain special devices.
    
    Rationale: Since the /var/log/audit filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in /var/log/audit .
  "
  impact 1.0
  describe mount("/var/log/audit") do
    it { should be_mounted }
  end
  describe mount("/var/log/audit") do
    its("options") { should include "nodev" }
  end
end