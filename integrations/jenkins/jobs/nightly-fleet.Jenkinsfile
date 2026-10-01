// Nightly fleet scan of every listed repository, then the fleet register.
@Library('sdt-pipeline') _

properties([pipelineTriggers([cron('H 1 * * *')]), disableConcurrentBuilds()])
sdtFleetScan(reposFile: 'integrations/jenkins/config/repos.txt', parallelism: 3)
