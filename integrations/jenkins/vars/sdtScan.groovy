/**
 * sdtScan: SDT security scan of one Bitbucket repository -> SonarQube + reports.
 *
 *   @Library('sdt-pipeline') _
 *   sdtScan(repo: 'mobile-app', branch: 'release/1.0')
 *   sdtScan(repo: 'web-portal', prId: '379', prBranch: 'feature/x', prBase: 'main')
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
 *   SDT_AGENT_LABEL           agent label to run on
 *   SDT_FLEET_DATABASE        optional SQLAlchemy URL of the fleet store
 *   SDT_QUALITY_GATE_ENFORCE  "1" fails the build on a failed gate (default: report only)
 */
def call(Map args = [:]) {
  def cfg = [
    repo            : args.repo ?: error('sdtScan: repo is required'),
    branch          : args.branch ?: '',
    prId            : args.prId ?: '',
    prBranch        : args.prBranch ?: '',
    prBase          : args.prBase ?: '',
    workspace       : args.workspace ?: env.SDT_WORKSPACE ?: error('sdtScan: set workspace or SDT_WORKSPACE'),
    sonarUrl        : args.sonarUrl ?: env.SDT_SONAR_URL ?: error('sdtScan: set sonarUrl or SDT_SONAR_URL'),
    sonarCredentials: args.sonarCredentials ?: env.SDT_SONAR_CREDENTIALS ?: 'sdt-sonar-token',
    gitCredentials  : args.gitCredentials ?: env.SDT_GIT_CREDENTIALS ?: 'sdt-bitbucket-ssh',
    image           : args.containsKey('image') ? args.image : (env.SDT_IMAGE ?: ''),
    agentLabel      : args.agentLabel ?: env.SDT_AGENT_LABEL ?: '',
    fleetDatabase   : args.fleetDatabase ?: env.SDT_FLEET_DATABASE ?: '',
    enforceGate     : (args.enforceGate ?: env.SDT_QUALITY_GATE_ENFORCE ?: '0').toString(),
  ]
  if (!cfg.branch && !cfg.prId) { error('sdtScan: give branch, or prId + prBranch + prBase') }
  def ref = cfg.prId ? cfg.prBranch : cfg.branch
  def scopeUrl = cfg.prId ? "https://bitbucket.org/${cfg.workspace}/${cfg.repo}/pull-requests/${cfg.prId}"
                          : "https://bitbucket.org/${cfg.workspace}/${cfg.repo}/src/${ref}"

  node(cfg.agentLabel) {
    def outcome = 'SUCCESS'
    try {
      stage('checkout') {
        dir('source') {
          def remote = [url: "git@bitbucket.org:${cfg.workspace}/${cfg.repo}.git"]
          if (cfg.gitCredentials != 'none') { remote.credentialsId = cfg.gitCredentials }
          checkout([$class: 'GitSCM', branches: [[name: ref]],
                    userRemoteConfigs: [remote],
                    // Full history: secrets in past commits are findings too.
                    extensions: [[$class: 'CloneOption', shallow: false, noTags: false],
                                 [$class: 'CleanBeforeCheckout']]])
          if (cfg.prBase) { sh "git fetch --no-tags origin '+refs/heads/${cfg.prBase}:refs/remotes/origin/${cfg.prBase}'" }
        }
      }
      writeFile file: '.sdt/scan.sh', text: libraryResource('sdt/scan.sh')
      writeFile file: '.sdt/reports.sh', text: libraryResource('sdt/reports.sh')
      def environment = ["SRC=${pwd()}/source", "OUT=${pwd()}/out", "REPO_SLUG=${cfg.repo}",
                         "BRANCH=${cfg.branch}", "PR_ID=${cfg.prId}", "PR_BRANCH=${cfg.prBranch}",
                         "PR_BASE=${cfg.prBase}", "WORKSPACE_NAME=${cfg.workspace}",
                         "SONAR_HOST_URL=${cfg.sonarUrl}", "SCOPE_URL=${scopeUrl}",
                         "FLEET_DATABASE=${cfg.fleetDatabase}", "QUALITY_GATE_ENFORCE=${cfg.enforceGate}"]
      withCredentials([string(credentialsId: cfg.sonarCredentials, variable: 'SONAR_TOKEN')]) {
        withEnv(environment) {
          withGitKey(cfg.gitCredentials) {
          inScanner(cfg.image) {
            stage('scan') {
              // A failed scan still produces reports from the SDT findings.
              def rc = sh(script: 'bash .sdt/scan.sh', returnStatus: true)
              if (rc == 2) { outcome = 'FAILURE'; echo 'quality gate failed' }
              else if (rc != 0) { outcome = 'FAILURE'; sh 'rm -f out/sonar-project-key' }
            }
            stage('reports') {
              if (sh(script: 'bash .sdt/reports.sh', returnStatus: true) != 0 && outcome == 'SUCCESS') { outcome = 'UNSTABLE' }
            }
          }
          }
        }
      }
    } finally {
      archiveArtifacts artifacts: 'out/*.docx, out/*.pdf, out/*.xlsx, out/fleet/*.pdf, out/fleet/*.xlsx, ' +
                                  'out/sdt/findings.json, out/sdt/findings.sarif, out/sdt/run-manifest.json, ' +
                                  'out/sbom.cdx.json, out/triage.json, out/quality-gate.txt, out/sonar-scanner.log',
                       allowEmptyArchive: true
      cleanWs()
    }
    currentBuild.result = outcome
  }
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
    docker.image(image).inside("--entrypoint= ${agentSocket}") { body() }
  } else {
    body()
  }
}
