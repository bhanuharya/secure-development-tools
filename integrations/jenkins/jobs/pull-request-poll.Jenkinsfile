// Starts a pull-request scan for every open pull request that has commits no scan has seen yet:
// a new pull request, or a new push to one. For a Jenkins that Bitbucket cannot reach with a webhook.
@Library('sdt-pipeline') _

properties([
  pipelineTriggers([cron('H/5 * * * *')]),
  disableConcurrentBuilds(),
  buildDiscarder(logRotator(numToKeepStr: '50')),
])

// The repositories to watch, and the job that scans one pull request (jobs/pull-request.Jenkinsfile).
def repos = ['web-portal']
def scanJob = 'sdt-pull-request'

def due = sdtPullRequestsDue(repos: repos)
currentBuild.description = due ? due.collect { "${it.repo} #${it.id}" }.join(', ') : 'nothing new'
for (pr in due) {
  build job: scanJob, wait: false, parameters: [
    string(name: 'reponame', value: pr.repo), string(name: 'pr_id', value: pr.id),
    string(name: 'pr_branch', value: pr.branch), string(name: 'pr_base', value: pr.base)]
}
