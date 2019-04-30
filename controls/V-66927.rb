is_on_siprnet = attribute('is_on_siprnet')
control 'V-66927' do
  title 'Oracle JRE 8 must have an exception.sites file present.'
  desc  "
    Utilizing a whitelist provides a configuration management method for
    allowing the execution of only authorized software. Using only authorized
    software decreases risk by limiting the number of potential vulnerabilities.
    The organization must identify authorized software programs and permit
    execution of authorized software. The process used to identify software
    programs that are authorized to execute on organizational information
    systems is commonly referred to as whitelisting. Verification of whitelisted
    software can occur either prior to execution or at system startup. This
    requirement applies to configuration management applications or similar
    types of applications designed to manage system processes and configurations
    (e.g., HBSS and software wrappers).
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000386'
  tag "gid": 'V-66927'
  tag "rid": 'SV-81417r1_rule'
  tag "stig_id": 'JRE8-UX-000130'
  tag "cci": 'CCI-001774'
  tag "nist": ['CM-7 (5) (c)', 'Rev_4']
  tag "check": 'If the system is on the SIPRNet, this requirement is NA.
  Navigate to the “exception.sites” file for Java:
  /etc/.java/deployment/exception.sites If the exception.sites file does not
  exist, it must be created. The exception.sites file is a text file containing
  single-line URLs for accepted risk sites. If there are no AO approved sites to
  be added to the configuration, it is acceptable for this file to be blank. If
  the “exception.sites” file does not exist, this is a finding. If the
  “exception.sites” file contains URLs that are not AO approved, this is a
  finding.'

  tag "fix": 'If the system is on the SIPRNet, this requirement is NA. Create
  the JRE exception.sites file: No default file exists. A text file named
  exception.sites, and the directory structure in which it is located must be
  manually created. The location must be aligned as defined in the
  deployment.properties file. /etc/.java/deployment/deployment.properties is an
  example.'

  if is_on_siprnet
    impact 0.0
    desc 'If the system is on the SIPRNET, therefore this requirement is NA'
    describe 'If the system is on the SIPRNET, therefore this requirement is NA' do
      skip 'If the system is on the SIPRNET, therefore this requirement is NA'
    end
  else
    describe file(attribute('deployment_exception_sites_file')) do
      it { should exist }
    end
  end
end
