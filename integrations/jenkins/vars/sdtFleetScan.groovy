/**
 * sdtFleetScan: nightly scan of every repository in the workspace, one sdtScan each,
 * followed by the fleet register (Excel) and summary.
 *
 *   @Library('sdt-pipeline') _
 *   sdtFleetScan(repos: ['mobile-app', 'web-portal'])                     // explicit list
 *   sdtFleetScan(reposFile: 'repos.txt')                                  // one "repo[@branch]" per line
 *
 * Repositories are scanned `parallelism` at a time; a failing repository never stops
 * the others, and shows up as incomplete coverage in the summary.
 */
def call(Map args = [:]) {
  List<String> lines = args.repos ?: []
  if (!lines && args.reposFile) {
    node(args.agentLabel ?: env.SDT_AGENT_LABEL ?: '') {
      checkout scm
      lines = readFile(args.reposFile).readLines().collect { it.trim() }.findAll { it && !it.startsWith('#') }
    }
  }
  if (!lines) { error('sdtFleetScan: give repos or reposFile') }
  int parallelism = (args.parallelism ?: 3) as int
  def results = [:]
  lines.collate(parallelism).each { batch ->
    def branches = [:]
    batch.each { line ->
      def (repo, branch) = line.contains('@') ? line.split('@', 2) as List : [line, args.defaultBranch ?: 'main']
      branches[repo] = {
        try {
          sdtScan(repo: repo, branch: branch)
          results[repo] = currentBuild.currentResult
        } catch (err) {
          results[repo] = "FAILED: ${err.message}"
          unstable("${repo}: ${err.message}")
        }
      }
    }
    parallel branches
  }
  echo "Fleet scan: " + results.collect { k, v -> "${k}=${v}" }.join(', ')
}
