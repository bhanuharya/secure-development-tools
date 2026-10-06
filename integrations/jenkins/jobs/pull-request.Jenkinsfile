// Pull-request scan: SonarQube decorates the PR and the quality gate is enforced, so a PR
// that adds a vulnerability or an unreviewed hotspot fails. Trigger from a Bitbucket
// webhook (Generic Webhook Trigger plugin) or from Bitbucket Branch Source.
@Library('sdt-pipeline') _

properties([
  parameters([
    string(name: 'reponame', description: 'Repository slug'),
    string(name: 'pr_id', description: 'Pull request id'),
    string(name: 'pr_branch', description: 'Source branch'),
    string(name: 'pr_base', defaultValue: 'main', description: 'Target branch'),
    string(name: 'pr_commit', defaultValue: '', description: 'The commit the scan was started for; empty scans whatever is newest'),
  ]),
])

currentBuild.description = "${params.reponame} PR #${params.pr_id}"
sdtScan(repo: params.reponame, prId: params.pr_id, prBranch: params.pr_branch, prBase: params.pr_base, prCommit: params.pr_commit?.trim(),
        enforceGate: '1')
