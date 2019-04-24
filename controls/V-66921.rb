is_on_siprnet = attribute('is_on_siprnet')
control 'V-66921' do
  title 'Oracle JRE 8 must set the option to enable online certificate validation'
  desc  "
    Online certificate validation provides a real-time option to validate a
    certificate. When enabled, if a certificate is presented, the status of the
    certificate is requested. The status is sent back as “current”, “expired”,
    or “unknown”. Online certificate validation provides a greater degree of
    validation of certificates when running a signed Java applet. Permitting
    execution of an applet with an invalid certificate may result in malware,
    system modification, invasion of privacy, and denial of service.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000175'
  tag "gid": 'V-66921'
  tag "rid": 'SV-81411r1_rule'
  tag "stig_id": 'JRE8-UX-000100'
  tag "cci": 'CCI-000185'
  tag "nist": ['IA-5 (2)(a)', 'Rev_4']
  tag "check": 'If the system is on the SIPRNet, this requirement is NA.
  Navigate to the system-level “deployment.properties” file for JRE.
  /etc/.java/deployment/deployment.properties If the key
  “deployment.security.validation.ocsp=true” is not present in the
  deployment.properties file, this is a finding. If the key
  “deployment.security.validation.ocsp.locked” is not present in the
  deployment.properties file, this is a finding. If the key
  “deployment.security.validation.ocsp” is set to “false”, this is a finding.'

  tag "fix": 'If the system is on the SIPRNet, this requirement is NA. Navigate
  to the system-level “deployment.properties” file for JRE.
  /etc/.java/deployment/deployment.properties Add the key
  “deployment.security.validation.ocsp=true” to the deployment.properties file.
  Add the key “deployment.security.validation.ocsp.locked” to the
  deployment.properties file.'

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/etc/.java/deployment/deployment.properties') do
      its('content') { should match(/deployment.security.validation.ocsp=true/) }
    end
    describe file('/etc/.java/deployment/deployment.properties') do
      its('content') { should match(/deployment.security.validation.ocsp.locked/) }
    end
  end
end
