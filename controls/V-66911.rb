control 'V-66911' do
  title 'Oracle JRE 8 must have a deployment.properties file present'
  desc  "
    By default no deployment.properties file exists; thus, no system-wide
    deployment exists. The file must be created. The deployment.properties file
    is used for specifying keys for the Java Runtime Environment. Each option in
    the Java control panel is represented by property keys. These keys adjust
    the options in the Java control panel based on the value assigned to that
    key. Without the deployment.properties file, setting particular options for
    the Java control panel is impossible.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000516'
  tag "gid": 'V-66911'
  tag "rid": 'SV-81401r1_rule'
  tag "stig_id": 'JRE8-UX-000030'
  tag "cci": 'CCI-000366'
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "check": 'Navigate to the system-level “deployment.properties” file for
  JRE. /etc/.java/deployment/deployment.properties If there is no file entitled
  “deployment.properties”, this is a finding.'

  tag "fix": 'Create the Java deployment properties file
  “/etc/.java/deployment/deployment.properties”'

  describe file('/etc/.java/deployment/deployment.properties') do
    it { should exist }
  end
end
