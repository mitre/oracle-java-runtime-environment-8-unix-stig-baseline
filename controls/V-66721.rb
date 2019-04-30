control 'V-66721' do
  title 'Oracle JRE 8 must have a deployment.config file present'
  desc  "
    By default no deployment.config file exists; thus, no system-wide
    deployment.properties file exists. The file must be created. The
    deployment.config file is used for specifying the location and execution of
    system-level properties for the Java Runtime Environment. Without the
    deployment.config file, setting particular options for the Java control
    panel is impossible.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000516'
  tag "gid": 'V-66721'
  tag "rid": 'SV-81211r1_rule'
  tag "stig_id": 'JRE8-UX-000010'
  tag "cci": 'CCI-000366'
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "check": 'Verify a JRE deployment configuration file exists as indicated:
  /etc/.java/deployment/deployment.config If the configuration file does not
  exist as indicated, this is a finding.'

  tag "fix": "Create a JRE deployment configuration file as indicated:

  /etc/.java/deployment/deployment.config"

  describe file(attribute('deployment_config_file')) do
    it { should exist }
  end
end
