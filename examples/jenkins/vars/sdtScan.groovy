// vars/sdtScan.groovy — drop into jenkins-shared-library vars/ (DevOps-owned).
// Reusable SDT gate for any pipeline. Advisory-first; strict via opt-in flag.
//
// Usage in a Jenkinsfile:
//   sdtScan(toolDir: '/opt/sdt', project: params.reponame, profile: 'full')
//   sdtScan(toolDir: '/opt/sdt', project: params.reponame, profile: 'full', strict: true)
//   sdtScan(toolDir: '/opt/sdt', project: 'hotsregistration', profile: 'pr',
//           base: "origin/${params.targetBranch}", head: env.GIT_COMMIT, strict: params.SDT_STRICT_MODE)
//
// Contract:
//   - Caller must have already checked out the target repo with FULL history.
//   - Always archives reports/**/* + plan.json (call post-Clean Workspace safe: archives first).
//   - Returns sdt exit code. Advisory (default): policy_failed -> UNSTABLE.
//     strict:true -> policy_failed -> FAILURE. Infra exits (2/3/5) always fail.
def call(Map cfg = [:]) {
  def toolDir = cfg.get('toolDir', '/opt/sdt')
  def project = cfg.get('project', env.JOB_BASE_NAME ?: 'unknown')
  def profile = cfg.get('profile', 'full')
  def base    = cfg.get('base', '')
  def head    = cfg.get('head', '')
  def strict  = cfg.get('strict', false)

  stage('SDT scan') {
    def code = sh(returnStatus: true, script: """
      export SDT_BIN='${toolDir}/sdt'
      export SDT_RULES_DIR='${toolDir}/rules/opengrep-rules'
      export SDT_TOOL_PDF='${toolDir}/tools/sdt_to_pdf.py'
      export SDT_PROFILE='${profile}'
      export SDT_PROJECT='${project}'
      ${base ? "export SDT_BASE='${base}'" : ':'}
      ${head ? "export SDT_HEAD='${head}'" : ':'}
      bash '${toolDir}/examples/jenkins/sdt-jenkins.sh'
    """)
    env.SDT_EXIT = "${code}"
    archiveArtifacts artifacts: 'reports/**/*, plan.json', allowEmptyArchive: false
    if (code == 0) {
      echo 'SDT: passed'
    } else if (code == 1) {
      if (strict) {
        error 'SDT: policy_failed (STRICT) — failing build. See reports/security-report.pdf'
      } else {
        unstable 'SDT: policy_failed (advisory) — see reports/security-report.pdf'
      }
    } else if (code == 4) {
      unstable "SDT: inconclusive (exit 4) — see reports/"
    } else {
      error "SDT: infra failure (exit ${code}) — see reports/"
    }
    return code
  }
}
