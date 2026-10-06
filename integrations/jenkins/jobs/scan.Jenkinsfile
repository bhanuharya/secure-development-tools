// One job for every on-demand scan. Pick the scan type when you build:
//   branch        the whole branch (release audit); the quality gate is reported, not enforced
//   pull-request  only what the PR adds over its target branch; a failed quality gate fails the build
@Library('sdt-pipeline') _

properties([
  buildDiscarder(logRotator(numToKeepStr: '50', artifactNumToKeepStr: '20')),
  parameters([
    string(name: 'reponame', defaultValue: '', description: 'Repository slug in the Bitbucket workspace'),
    choice(name: 'scan_type', choices: ['branch', 'pull-request'],
           description: 'branch: scan the whole branch. pull-request: scan only what the PR adds (fill pr_id and pr_base).'),
    string(name: 'branch', defaultValue: 'main', description: 'Branch to scan; for a pull request, its source branch'),
    string(name: 'pr_id', defaultValue: '', description: 'Pull request only: the PR number'),
    string(name: 'pr_base', defaultValue: 'main', description: 'Pull request only: the target branch'),
    string(name: 'merge_commit', defaultValue: '',
           description: 'Pull request already merged: its merge (or squash) commit. Empty for an open pull request.'),
    choice(name: 'codebase', choices: ['other', 'frontend', 'backend', 'mobile'], description: 'Kind of codebase (for reporting)'),
  ]),
])

def repo = params.reponame?.trim()
def branch = params.branch?.trim()
if (!repo) { error 'reponame is required' }
if (!branch) { error 'branch is required' }

if (params.scan_type == 'pull-request') {
  def prId = params.pr_id?.trim()
  def prBase = params.pr_base?.trim()
  if (!(prId ==~ /\d+/)) { error 'pull-request scan: pr_id must be the PR number' }
  if (!prBase) { error 'pull-request scan: pr_base (target branch) is required' }
  def mergeCommit = params.merge_commit?.trim()
  if (mergeCommit && !(mergeCommit ==~ /[0-9a-fA-F]{7,40}/)) { error 'pull-request scan: merge_commit must be a commit hash' }
  currentBuild.description = "${repo} PR #${prId}: ${branch} → ${prBase}${mergeCommit ? ', merged in ' + mergeCommit : ''} (${params.codebase})"
  sdtScan(repo: repo, prId: prId, prBranch: branch, prBase: prBase, prMergeCommit: mergeCommit, enforceGate: '1')
} else {
  currentBuild.description = "${repo} @ ${branch} (${params.codebase})"
  sdtScan(repo: repo, branch: branch)
}
