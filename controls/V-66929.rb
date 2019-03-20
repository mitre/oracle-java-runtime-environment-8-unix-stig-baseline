is_on_siprnet = attribute('is_on_siprnet')
control 'V-66929' do
  title 'Oracle JRE 8 must enable the dialog to enable users to check publisher certificates for revocation'
  desc  "
    A certificate revocation list is a directory which contains a list of certificates that have been revoked for various reasons. Certificates may be revoked due to improper issuance, compromise of the certificate, and failure to adhere to policy. Therefore, any certificate found on a CRL should not be trusted. Permitting execution of an applet published with a revoked certificate may result in spoofing, malware, system modification, invasion of privacy, and denial of service.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000401'
  tag "gid": 'V-66929'
  tag "rid": 'SV-81419r1_rule'
  tag "stig_id": 'JRE8-UX-000150'
  tag "cci": 'CCI-001991'
  tag "nist": ['IA-5 (2) (d)', 'Rev_4']
  tag "check": 'If the system is on the SIPRNet, this requirement is NA. Navigate to the system-level “deployment.properties” file for JRE. /etc/.java/deployment/deployment.properties If the key “deployment.security.validation.crl=true” is not present in the deployment.properties file, or is set to “false”, this is a finding. If the key “deployment.security.validation.crl.locked” is not present in the deployment.properties file, this is a finding.'

  tag "fix": 'If the system is on the SIPRNet, this requirement is NA. Enable the “Check certificates for revocation using Certificate Revocation Lists (CRL)” option. Navigate to the system-level “deployment.properties” file for JRE. /etc/.java/deployment/deployment.properties Add the key “deployment.security.validation.crl=true” to the deployment.properties file. Add the key “deployment.security.validation.crl.locked” to the deployment.properties file'

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/etc/.java/deployment/deployment.properties') do
      its('content') { should match(/deployment.security.validation.crl=true/) }
    end
    describe file('/etc/.java/deployment/deployment.properties') do
      its('content') { should match(/deployment.security.validation.crl.locked/) }
    end
  end
end
