control 'V-66935' do
  title 'Oracle JRE 8 must remove previous versions when the latest version is installed'
  desc  "
    Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000454'
  tag "gid": 'V-66935'
  tag "rid": 'SV-81425r1_rule'
  tag "stig_id": 'JRE8-UX-000190'
  tag "cci": 'CCI-002617'
  tag "nist": ['SI-2 (6)', 'Rev_4']
  tag "check": 'Review the system configuration to ensure old versions of JRE have been removed. There are two ways to uninstall Java. Use the method that you used when you installed Java. For example, if you used RPM to install Java, then use the RPM uninstall method. If RPM is installed, first query to ascertain that JRE was installed using RPM. Search for the JRE package by typing: # rpm -qa | grep -i jre If RPM reports a package similar to jre-<version>-fcs, then JRE is installed with RPM. If JRE is not installed using RPM, skip to Self-extracting file uninstall. To uninstall Java via RPM, type: # rpm -e jre-<version>-fcs Self-extracting file uninstall: 1. Browse folders to ascertain where JRE is installed. Common locations are /usr/java/jre_<version> or opt/jre_nb/jre_<version>/bin/java/ 2. When you have located the directory, you may delete the directory by using the following command: Note: Ensure JRE is not already installed using RPM before removing the directory. # rm -r /<path to jre>/jre<version> Ensure only one instance of JRE is installed on the system. # ps -ef | grep -I jre If more than one instance of JRE is running, this is a finding.'

  tag "fix": 'Remove previous versions of JRE. RPM uninstall: # rpm -e jre-<version>-fcs Self-extracting file uninstall: # rm -r jre<version> Perform for all out of date instances of JRE.'

  get_previous_jreversions_installed = command('rpm -qa | grep java- | grep -v ^java-1.8 |  rpm -qa | grep java- | grep -v ^java-1.8 | wc -l').stdout.strip
  get_previous_jreversions_installed2 = command("alternatives --list | grep '^java\s' | grep -v java-1.8 | wc -l").stdout.strip

  describe.one do
    describe 'The number of previous versions of JRE installed' do
      subject { get_previous_jreversions_installed }
      it { should cmp 0 }
    end

    describe 'The number of jre versions installed' do
      subject { command('ps -ef | grep -I jre | wc -l').stdout }
      it { should eq 1 }
    end
    describe 'The number of previous versions of JRE installed' do
      subject { get_previous_jreversions_installed2 }
      it { should eq '0' }
    end
  end
end
