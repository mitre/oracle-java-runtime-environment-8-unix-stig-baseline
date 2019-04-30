control 'V-66937' do
  title 'The version of Oracle JRE 8 running on the system must be the most
  current available'
  desc "
   Oracle JRE 8 is being continually updated by the vendor in order to address
   identified security vulnerabilities. Running an older version of the JRE can
   introduce security vulnerabilities to the system.
  "
  impact 0.7
  tag "severity": 'high'
  tag "gtitle": 'SRG-APP-000456'
  tag "gid": 'V-66937'
  tag "rid": 'SV-81427r1_rule'
  tag "stig_id": 'JRE8-UX-000180'
  tag "cci": 'CCI-002605'
  tag "nist": ['SI-2 c', 'Rev_4']
  tag "check": 'Review the system configuration to ensure old versions of JRE
  have been removed. There are two ways to uninstall Java. Use the method that
  you used when you installed Java. For example, if you used RPM to install
  Java, then use the RPM uninstall method. If RPM is installed, first query to
  ascertain that JRE was installed using RPM. Search for the JRE package by
  typing: # rpm -qa | grep -i jre If RPM reports a package similar to
  jre-<version>-fcs, then JRE is installed with RPM. If JRE is not installed
  using RPM, skip to Self-extracting file uninstall. To uninstall Java via RPM,
  type: # rpm -e jre-<version>-fcs Self-extracting file uninstall: 1. Browse
  folders to ascertain where JRE is installed. Common locations are
  /usr/java/jre_<version> or opt/jre_nb/jre_<version>/bin/java/ 2. When you have
  located the directory, you may delete the directory by using the following
  command: Note: Ensure JRE is not already installed using RPM before removing
  the directory. # rm -r /<path to jre>/jre<version> Ensure only one instance of
  JRE is installed on the system. # ps -ef | grep -I jre If more than one
  instance of JRE is running, this is a finding.'

  tag "fix": 'Remove previous versions of JRE. RPM uninstall: # rpm -e
  jre-<version>-fcs Self-extracting file uninstall: # rm -r jre<version> Perform
  for all out of date instances of JRE.'

  java_cmd = command('java -version').stderr&.lines&.first&.strip&.split&.last
  describe 'The java version installed' do
    it "should be attribute('java_version" do
      expect(java_cmd).to(match attribute('java_version'))
    end
  end
end
