// On-demand scan of one repository branch: the parameters of the existing
// "sonarqube-scanner" job, now a thin wrapper around the shared library.
@Library('sdt-pipeline') _

properties([
  disableConcurrentBuilds(),
  buildDiscarder(logRotator(numToKeepStr: '50', artifactNumToKeepStr: '20')),
  parameters([
    string(name: 'reponame', defaultValue: '', description: 'Repository slug in the Bitbucket workspace'),
    string(name: 'branch', defaultValue: 'main', description: 'Branch to scan'),
    choice(name: 'codebase', choices: ['other', 'frontend', 'backend', 'mobile'], description: 'Kind of codebase (for reporting)'),
  ]),
])

if (!params.reponame) { error 'reponame is required' }
currentBuild.description = "${params.reponame} @ ${params.branch} (${params.codebase})"
sdtScan(repo: params.reponame, branch: params.branch)
