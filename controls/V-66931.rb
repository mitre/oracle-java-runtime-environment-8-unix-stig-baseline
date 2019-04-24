is_on_siprnet = attribute('is_on_siprnet')
control 'V-66931' do
  title 'Oracle JRE 8 must lock the option to enable users to check publisher
  certificates for revocation'
  desc  "
    Certificates may be revoked due to improper issuance, compromise of the
    certificate, and failure to adhere to policy. Therefore, any certificate
    found revoked on a CRL or via Online Certificate Status Protocol (OCSP)
    should not be trusted. Permitting execution of an applet published with a
    revoked certificate may result in spoofing, malware, system modification,
    invasion of privacy, and denial of service. Ensuring users cannot change
    these settings assures a more consistent security profile.
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000401'
  tag "gid": 'V-66931'
  tag "rid": 'SV-81421r1_rule'
  tag "stig_id": 'JRE8-UX-000160'
  tag "cci": 'CCI-001991'
  tag "nist": ['IA-5 (2) (d)', 'Rev_4']
  tag "check": 'If the system is on the SIPRNet, this requirement is NA.
  Navigate to the system-level “deployment.properties” file for JRE.
  /etc/.java/deployment/deployment.properties If the key
  “deployment.security.revocation.check=ALL_CERTIFICATES” is not present, or is
  set to “PUBLISHER_ONLY”, or “NO_CHECK”, this is a finding. If the key
  “deployment.security.revocation.check.locked” is not present, this is a
  finding.'

  tag "fix": 'If the system is on the SIPRNet, this requirement is NA. Navigate
  to the system-level “deployment.properties” file for JRE.
  /etc/.java/deployment/deployment.properties Add the key
  “deployment.security.revocation.check=ALL_CERTIFICATES” to the
  deployment.properties file. Add the key
  “deployment.security.revocation.check.locked” to the deployment.properties
  file'

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file('/etc/.java/deployment/deployment.properties') do
      its('content') { should match(/deployment.security.revocation.check=ALL_CERTIFICATES/) }
    end
    describe file('/etc/.java/deployment/deployment.properties') do
      its('content') { should match(/deployment.security.revocation.check.locked/) }
    end
  end
end
