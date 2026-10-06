/**
 * sdtPullRequestsDue: the open pull requests that have commits no scan has seen yet.
 *
 * For a Jenkins that Bitbucket cannot reach with a webhook. A job with a timer asks for the list and
 * starts a scan for each entry (jobs/pull-request-poll.Jenkinsfile):
 *
 *   sdtPullRequestsDue(repos: ['web-portal', 'mobile-app']).each { pr ->
 *     build job: 'sdt-pull-request', wait: false, parameters: [...pr.repo, pr.id, pr.branch, pr.base...]
 *   }
 *
 * Returns a list of [repo, id, branch, base, commit]. Each commit is returned once: what was returned
 * is remembered in the job's workspace. Uses SDT_WORKSPACE, SDT_BITBUCKET_API_CREDENTIALS and
 * SDT_BITBUCKET_API_USER (see sdtScan); the token only needs to read pull requests.
 */
def call(Map args = [:]) {
  def repos = args.repos ?: error('sdtPullRequestsDue: repos is required')
  def workspace = args.workspace ?: env.SDT_WORKSPACE ?: error('sdtPullRequestsDue: set workspace or SDT_WORKSPACE')
  def credentials = args.prCommentCredentials ?: env.SDT_BITBUCKET_API_CREDENTIALS ?: error('sdtPullRequestsDue: set prCommentCredentials or SDT_BITBUCKET_API_CREDENTIALS')
  def user = args.prCommentUser ?: env.SDT_BITBUCKET_API_USER ?: ''
  def due = []
  node(args.agentLabel ?: env.SDT_AGENT_LABEL ?: '') {
    for (name in ['sdt_common.py', 'pr_comment.py', 'pr_poll.py']) {
      writeFile file: ".sdt/${name}", text: libraryResource("sdt/${name}")
    }
    withCredentials([string(credentialsId: credentials, variable: 'BITBUCKET_TOKEN')]) {
      withEnv(["WORKSPACE_NAME=${workspace}", "BITBUCKET_USER=${user}", "SDT_POLL_REPOS=${repos.join(' ')}"]) {
        def lines = sh(script: 'python3 .sdt/pr_poll.py', returnStdout: true).trim()
        for (line in (lines ? lines.split('\n') : [])) {
          def field = line.split('\t')
          due << [repo: field[0], id: field[1], branch: field[2], base: field[3], commit: field[4]]
        }
      }
    }
  }
  return due
}
