/**
 * sdtScan: SDT security scan of one Bitbucket repository -> SonarQube + reports.
 *
 *   @Library('sdt-pipeline') _
 *   sdtScan(repo: 'mobile-app', branch: 'release/1.0')
 *   sdtScan(repo: 'web-portal', prId: '379', prBranch: 'feature/x', prBase: 'main')
 *   sdtScan(repo: 'web-portal', prId: '379', prBranch: 'feature/x', prBase: 'main', prMergeCommit: 'a1b2c3d')
 *
 * prCommit is the commit a scan was started for (by a webhook or sdtPullRequestsDue). When the pull request
 * has newer commits by the time the scan gets its turn, it stops: the newer commit has its own scan.
 *
 * prMergeCommit scans a pull request that is already merged: the merge (or squash) commit is
 * compared with its first parent, the target branch as it was before the merge.
 *
 * Every setting has a default from the global environment (Manage Jenkins > System >
 * Global properties) so a prod Jenkins only sets what differs. Credentials are Jenkins
 * credential ids, never files:
 *
 *   SDT_SONAR_URL             SonarQube URL
 *   SDT_SONAR_CREDENTIALS     "Secret text" credential holding the Sonar token
 *   SDT_GIT_CREDENTIALS       "SSH username with private key" credential for Bitbucket;
 *                             "none" = use the agent user's own SSH key (~/.ssh)
 *   SDT_WORKSPACE             Bitbucket workspace (e.g. my-workspace)
 *   SDT_IMAGE                 scanner image (docker/Dockerfile); empty = tools on the agent
 *   SDT_DOCKER_ARGS           extra "docker run" arguments for the scanner container, e.g. the volume
 *                             that keeps state between scans: "-v sdt-state:/var/lib/sdt"
 *   SDT_AGENT_LABEL           agent label to run on
 *   SDT_CLONE_MINUTES         time limit of the clone, in minutes (default 30; the git plugin's own is 10)
 *   SDT_CLONE_CACHE           optional folder on the agent that keeps a mirror of every scanned repository, so a
 *                             scan fetches only what changed since the last one instead of the whole history.
 *                             Empty (default): every scan clones in full
 *   SDT_FLEET_DATABASE        optional SQLAlchemy URL of the fleet store
 *   SDT_QUALITY_GATE_ENFORCE  "1" fails the build on a failed gate (default: report only)
 *   SDT_BITBUCKET_API_CREDENTIALS  "Secret text" credential with a Bitbucket token that may comment on pull
 *                             requests (and write to the repository, to attach the report). Set: every
 *                             pull-request scan comments its result on the pull request. Empty: no comment
 *   SDT_BITBUCKET_API_USER    the account email, when that token is an API token; empty for an access token
 *   SDT_REPORTS_REPO          repository (slug, or workspace/slug) every scan commits its report to, with the
 *                             same token; the pull-request comment then links it. Empty: no reports repository
 *   SDT_PR_SOURCE_REPORT      "1" (default): a pull request scan also scans its whole source branch, as a branch
 *                             scan would, and reports it in out/source-branch/. "0": the pull request report only
 */
def call(Map args = [:]) {
  def cfg = [
    repo            : repoSlug(args.repo),
    branch          : args.branch ?: '',
    prId            : args.prId ?: '',
    prBranch        : args.prBranch ?: '',
    prBase          : args.prBase ?: '',
    prMergeCommit   : args.prMergeCommit ?: '',
    prCommit        : args.prCommit ?: '',
    workspace       : args.workspace ?: env.SDT_WORKSPACE ?: error('sdtScan: set workspace or SDT_WORKSPACE'),
    sonarUrl        : args.sonarUrl ?: env.SDT_SONAR_URL ?: error('sdtScan: set sonarUrl or SDT_SONAR_URL'),
    sonarCredentials: args.sonarCredentials ?: env.SDT_SONAR_CREDENTIALS ?: 'sdt-sonar-token',
    gitCredentials  : args.gitCredentials ?: env.SDT_GIT_CREDENTIALS ?: 'sdt-bitbucket-ssh',
    // Bitbucket Cloud serves git over SSH at ssh.bitbucket.org (bitbucket.org stops on 12 Nov 2026).
    sshHost         : args.sshHost ?: env.SDT_BITBUCKET_SSH_HOST ?: 'ssh.bitbucket.org',
    image           : args.containsKey('image') ? args.image : (env.SDT_IMAGE ?: ''),
    agentLabel      : args.agentLabel ?: env.SDT_AGENT_LABEL ?: '',
    cloneMinutes    : (args.cloneMinutes ?: env.SDT_CLONE_MINUTES ?: '30') as int,
    cloneCache      : args.cloneCache ?: env.SDT_CLONE_CACHE ?: '',
    fleetDatabase   : args.fleetDatabase ?: env.SDT_FLEET_DATABASE ?: '',
    enforceGate     : (args.enforceGate ?: env.SDT_QUALITY_GATE_ENFORCE ?: '0').toString(),
    prCommentCredentials: args.prCommentCredentials ?: env.SDT_BITBUCKET_API_CREDENTIALS ?: '',
    prCommentUser   : args.prCommentUser ?: env.SDT_BITBUCKET_API_USER ?: '',
    reportsRepo     : args.reportsRepo ?: env.SDT_REPORTS_REPO ?: '',
    sourceReport    : (args.containsKey('sourceReport') ? args.sourceReport : (env.SDT_PR_SOURCE_REPORT ?: '1')).toString(),
  ]
  if (!cfg.branch && !cfg.prId) { error('sdtScan: give branch, or prId + prBranch + prBase') }
  if (cfg.prMergeCommit && !(cfg.prId && cfg.prBase)) { error('sdtScan: prMergeCommit needs prId and prBase') }
  if (cfg.prMergeCommit && !(cfg.prMergeCommit ==~ /[0-9a-fA-F]{7,40}/)) { error('sdtScan: prMergeCommit must be a commit hash') }
  // A merged pull request is checked out from its target branch: the source branch may be gone.
  def ref = cfg.prMergeCommit ? cfg.prBase : (cfg.prId ? cfg.prBranch : cfg.branch)
  def scopeUrl = cfg.prId ? "https://bitbucket.org/${cfg.workspace}/${cfg.repo}/pull-requests/${cfg.prId}"
                          : "https://bitbucket.org/${cfg.workspace}/${cfg.repo}/src/${ref}"

  // For out/timings.tsv: how long the scan waited for its turn and an agent, and how long the clone took.
  long asked = System.currentTimeMillis()
  oneAtATime("sdt-scan/${cfg.workspace}/${cfg.repo}") {
  node(cfg.agentLabel) {
    def outcome = 'SUCCESS'
    long began = System.currentTimeMillis()
    try {
      stage('checkout') {
        def remote = [url: "git@${cfg.sshHost}:${cfg.workspace}/${cfg.repo}.git"]
        if (cfg.gitCredentials != 'none') { remote.credentialsId = cfg.gitCredentials }
        String mirror = cfg.cloneCache ? updateMirror(cfg, remote.url) : ''
        // Full history: secrets in past commits are findings too. That takes a repository with large
        // files in its history longer than the git plugin's 10 minutes. With a mirror, objects it
        // already has are borrowed instead of fetched.
        def cloneOption = [$class: 'CloneOption', shallow: false, noTags: false, timeout: cfg.cloneMinutes]
        if (mirror) { cloneOption.reference = mirror }
        dir('source') {
          checkout([$class: 'GitSCM', branches: [[name: ref]],
                    userRemoteConfigs: [remote],
                    extensions: [cloneOption, [$class: 'CleanBeforeCheckout']]])
          if (mirror) {
            // Copy the borrowed objects in, so the checkout stands alone: a scanner container does not see
            // the mirror's path, and the mirror may be pruned once this scan has finished.
            sh 'git repack -a -d -q && rm -f .git/objects/info/alternates'
          }
          if (cfg.prMergeCommit) {
            // The target branch now contains the pull request. Scan the merge commit and, in this
            // workspace only, point the target branch at what it was before the merge.
            sh "git checkout -q --detach '${cfg.prMergeCommit}^{commit}' && " +
               "git update-ref 'refs/remotes/origin/${cfg.prBase}' '${cfg.prMergeCommit}^1'"
          } else if (cfg.prBase) {
            // The checkout normally fetched every branch already; fetch the target only if it did not.
            withGitKey(cfg.gitCredentials) {
              sh "git rev-parse -q --verify 'refs/remotes/origin/${cfg.prBase}^{commit}' >/dev/null || " +
                 "git fetch --no-tags origin '+refs/heads/${cfg.prBase}:refs/remotes/origin/${cfg.prBase}'"
            }
          }
        }
      }
      if (cfg.prCommit && !cfg.prMergeCommit) {
        def head = dir('source') { sh(script: 'git rev-parse HEAD', returnStdout: true).trim() }
        if (!head.startsWith(cfg.prCommit) && !cfg.prCommit.startsWith(head)) {
          echo "sdtScan: started for ${cfg.prCommit}, but the pull request is now at ${head}: that commit has its own scan"
          currentBuild.description = "${currentBuild.description ?: ''} superseded".trim()
          currentBuild.result = 'NOT_BUILT'
          return
        }
      }
      long cloned = System.currentTimeMillis()
      for (name in ['scan.sh', 'reports.sh', 'sdt_common.py', 'pr_comment.py', 'publish_report.py']) {
        writeFile file: ".sdt/${name}", text: libraryResource("sdt/${name}")
      }
      // Jenkins environment names are case-insensitive: job parameters such as "branch" or
      // "pr_id" would swallow BRANCH / PR_ID, so the scope is passed as SDT_SCAN_* and
      // renamed in the shell (see runScript).
      def environment = ["SRC=${pwd()}/source", "OUT=${pwd()}/out", "REPO_SLUG=${cfg.repo}",
                         "SDT_SCAN_BRANCH=${cfg.branch}", "SDT_SCAN_PR_ID=${cfg.prId}",
                         "SDT_SCAN_PR_BRANCH=${cfg.prBranch}", "SDT_SCAN_PR_BASE=${cfg.prBase}",
                         "WORKSPACE_NAME=${cfg.workspace}", "SDT_BITBUCKET_SSH_HOST=${cfg.sshHost}",
                         "SONAR_HOST_URL=${cfg.sonarUrl}", "SCOPE_URL=${scopeUrl}",
                         "FLEET_DATABASE=${cfg.fleetDatabase}", "QUALITY_GATE_ENFORCE=${cfg.enforceGate}",
                         "BITBUCKET_USER=${cfg.prCommentUser}", "SDT_REPORTS_REPO=${cfg.reportsRepo}",
                         "SDT_QUEUE_MS=${began - asked}", "SDT_CHECKOUT_MS=${cloned - began}"]
      withCredentials([string(credentialsId: cfg.sonarCredentials, variable: 'SONAR_TOKEN')]) {
        withEnv(environment) {
          withGitKey(cfg.gitCredentials) {
          inScanner(cfg.image) {
            stage('scan') {
              // A failed scan still produces reports from the SDT findings.
              def rc = runScript('bash .sdt/scan.sh')
              if (rc == 2) { outcome = 'FAILURE'; echo 'quality gate failed' }
              else if (rc != 0) { outcome = 'FAILURE'; sh 'rm -f out/sonar-project-key' }
            }
            stage('reports') {
              if (runScript('bash .sdt/reports.sh') != 0 && outcome == 'SUCCESS') { outcome = 'UNSTABLE' }
            }
            if (cfg.prId && !cfg.prMergeCommit && cfg.sourceReport == '1') {
              stage('source branch') {
                // The pull request's report lists only what it adds. The whole source branch is scanned too,
                // exactly as a branch scan of it would be (its own SonarQube branch analysis, history and
                // report), into out/source-branch/. Its quality gate does not decide this build.
                withEnv(["OUT=${pwd()}/out/source-branch", "SDT_SCAN_BRANCH=${cfg.prBranch}", 'SDT_SCAN_PR_ID=',
                         'SDT_SCAN_PR_BRANCH=', 'SDT_SCAN_PR_BASE=', 'SDT_QUEUE_MS=', 'SDT_CHECKOUT_MS=',
                         "SCOPE_URL=https://bitbucket.org/${cfg.workspace}/${cfg.repo}/src/${cfg.prBranch}"]) {
                  if (!sourceBranchScan() && outcome == 'SUCCESS') { outcome = 'UNSTABLE' }
                }
              }
            }
            if (cfg.prCommentCredentials && (cfg.reportsRepo || cfg.prId)) {
              stage('publish') {
                // The report in the reports repository, then pass or fail on the pull request.
                // Neither fails the build.
                withCredentials([string(credentialsId: cfg.prCommentCredentials, variable: 'BITBUCKET_TOKEN')]) {
                  if (cfg.reportsRepo && runScript('python3 .sdt/publish_report.py') != 0) {
                    echo 'the report was not published to the reports repository'
                  }
                  if (cfg.prId && runScript('python3 .sdt/pr_comment.py') != 0) {
                    echo 'the pull request comment was not posted'
                  }
                }
              }
            }
          }
          }
        }
      }
    } finally {
      archiveArtifacts artifacts: 'out/*.docx, out/target-branch/*.docx, out/*.xlsx, out/fleet/*.pdf, out/fleet/*.xlsx, ' +
                                  'out/source-branch/*.docx, out/source-branch/sdt/findings.json, ' +
                                  'out/source-branch/quality-gate.txt, out/source-branch/timings.tsv, ' +
                                  'out/sdt/findings.json, out/sdt/findings-new.json, out/sdt/findings.sarif, ' +
                                  'out/sdt/endpoints.json, out/sdt/run-manifest.json, ' +
                                  'out/sbom.cdx.json, out/triage.json, out/quality-gate.txt, out/sonar-scanner.log, out/timings.tsv, ' +
                                  'out/report-state.json, ' +
                                  'out/ai-change-review.md, out/ai-change-review.json, out/sonar-pull-request.json',
                       allowEmptyArchive: true
      cleanWs()
    }
    currentBuild.result = outcome
  }
  }
}

/**
 * Scans of one repository run one after another, since they share its SonarQube project and scan
 * history; scans of different repositories run side by side. Waiting happens before an agent is taken.
 */
private void oneAtATime(String resource, Closure body) {
  boolean started = false
  try {
    lock(resource) { started = true; body() }
  } catch (NoSuchMethodError e) {
    if (started) { throw e }
    echo 'sdtScan: Lockable Resources plugin not installed; scans of the same repository are not kept apart'
    body()
  }
}

/**
 * The repository slug as typed, without the slips that broke a scan halfway: 'web-portal/' and 'web-portal.git'
 * give 'web-portal'. A name that is still not a slug stops here. A slash in it used to clone and scan, then
 * fail at SonarQube (invalid project key) and write the report into a folder the build does not keep.
 */
private String repoSlug(raw) {
  String typed = (raw ?: '').toString().trim()
  if (!typed) { error('sdtScan: repo is required') }
  String slug = typed.replaceAll('^/+|/+$', '').replaceFirst('(?i)\\.git$', '')
  if (!(slug ==~ /[A-Za-z0-9._-]+/)) {
    error("sdtScan: '${typed}' is not a repository slug: use only the repository's name in the Bitbucket " +
          "workspace (letters, digits, '.', '_' and '-'), for example web-portal")
  }
  return slug
}

/**
 * Bring this repository's mirror in SDT_CLONE_CACHE up to date (cloning it on the first scan) and return its path,
 * or '' when that fails: the checkout then clones in full, as without a cache. Scans of one repository run one
 * at a time (oneAtATime), so two scans never update the same mirror. Mirrors unused for 30 days are removed.
 */
private String updateMirror(Map cfg, String url) {
  String mirror = "${cfg.cloneCache}/${cfg.workspace}/${cfg.repo}.git"
  int status = 1
  withGitKey(cfg.gitCredentials) {
    status = sh(returnStatus: true, script: """
      set -eu
      m='${mirror}'
      if [ -d "\$m/objects" ]; then
        timeout ${cfg.cloneMinutes}m git -C "\$m" fetch -q --prune --tags origin
      else
        rm -rf "\$m" "\$m.tmp"; mkdir -p "\$(dirname "\$m")"
        timeout ${cfg.cloneMinutes}m git clone -q --mirror '${url}' "\$m.tmp"
        mv "\$m.tmp" "\$m"
      fi
      touch "\$m"
      find '${cfg.cloneCache}' -mindepth 2 -maxdepth 2 -name '*.git' -type d -mtime +30 -prune -exec rm -rf {} + || true
    """)
  }
  if (status != 0) {
    echo "sdtScan: clone cache ${mirror} could not be updated (exit ${status}); cloning in full"
    return ''
  }
  return mirror
}

/**
 * The branch scan of a pull request's source branch, after the pull request's own scan (sdtScan, stage
 * 'source branch'; OUT and the scope are set by the caller). That scan left files in the checkout (its
 * baseline, the scanner's work folder, fetched packages), so the checkout is restored to the commit first.
 * Returns false when no report came out; a failed quality gate is not a failure here.
 */
private boolean sourceBranchScan() {
  if (sh(script: 'git -C source reset -q --hard && git -C source clean -qffdx', returnStatus: true) != 0) {
    echo 'sdtScan: the checkout could not be restored; the source branch is not scanned'
    return false
  }
  int rc = runScript('bash .sdt/scan.sh')
  if (rc != 0 && rc != 2) { sh 'rm -f "$OUT/sonar-project-key"' }  // report from the SDT findings, as above
  if (runScript('bash .sdt/reports.sh') != 0) {
    echo 'sdtScan: the source branch report failed (the pull request report is complete)'
    return false
  }
  return true
}

/** Run a .sdt script with BRANCH / PR_* restored from SDT_SCAN_*; returns the exit code. */
private int runScript(String command) {
  return sh(script: 'BRANCH="$SDT_SCAN_BRANCH" PR_ID="$SDT_SCAN_PR_ID" PR_BRANCH="$SDT_SCAN_PR_BRANCH" ' +
                    "PR_BASE=\"\$SDT_SCAN_PR_BASE\" ${command}", returnStatus: true)
}

/** Load the Bitbucket key into an ssh-agent, unless the agent user's own key is used ("none"). */
private void withGitKey(String credentials, Closure body) {
  if (credentials == 'none') { body() } else { sshagent([credentials]) { body() } }
}

/** Run the body in the scanner image when one is configured, else on the agent. */
private void inScanner(String image, Closure body) {
  if (image) {
    // Forward the ssh-agent socket so private git dependencies resolve inside the container.
    def agentSocket = env.SSH_AUTH_SOCK ? "-v ${env.SSH_AUTH_SOCK}:${env.SSH_AUTH_SOCK} -e SSH_AUTH_SOCK" : ''
    docker.image(image).inside("--entrypoint= ${agentSocket} ${env.SDT_DOCKER_ARGS ?: ''}") { body() }
  } else {
    body()
  }
}
