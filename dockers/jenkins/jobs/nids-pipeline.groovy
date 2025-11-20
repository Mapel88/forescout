// dockers/jenkins/jobs/nids-pipeline.groovy
pipelineJob('nids-package-build-and-test') {
    description('Builds and tests NIDS configuration packages for RHEL and Ubuntu.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/mapel88/forescout.git') 
                    }
                    branch('*/master')
                }
            }
            scriptPath('JenkinsFile')
            lightweight()
        }
    }
}