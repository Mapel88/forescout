# NIDS Configuration Repo

Lightweight repository that builds and validates a small NIDS configuration CLI packaged as DEB/RPM,
and provides a local Jenkins instance for building/testing using Docker-based agents.

## Prerequisites
- Docker Desktop (with Docker Compose)
- git (for checking out repo)

## Quick start (local)
1. Open a terminal in the repo root.
2. Build agent images:
   docker compose -f dockers/agents-compose.yaml build
3. Build and run Jenkins:
   docker compose -f dockers/jenkins-compose.yaml up -d --build
4. Access Jenkins:
   URL: https://localhost:8080
   Admin credentials (example in this repo): `admin` / `Aa123456`

## Pipeline / How to run
- The Jenkins pipeline is defined in [Jenkinsfile](Jenkinsfile).
- It builds:
  - DEB on the `ubuntu-agent` using [dockers/ubuntu-agent/Dockerfile](dockers/ubuntu-agent/Dockerfile) and [dockers/ubuntu-agent/control](dockers/ubuntu-agent/control)
  - RPM on the `rhel-agent` using [dockers/alma-agent/Dockerfile](dockers/alma-agent/Dockerfile) and [dockers/alma-agent/nids-config.spec](dockers/alma-agent/nids-config.spec)
- After building, the pipeline validates packages by installing and running the CLI.

## CLI tool
- Main script: [nids-config.py](nids-config.py)
  - Key classes: [`NIDSConfig`](nids-config.py), [`NetworkInterface`](nids-config.py)
- Default config: [nids-config.yaml](nids-config.yaml)

## Jenkins configuration
- Dockerized Jenkins master setup:
  - Compose file: [dockers/jenkins-compose.yaml](dockers/jenkins-compose.yaml)
  - JCasC config: [dockers/jenkins/master/jenkins-casc.yaml](dockers/jenkins/master/jenkins-casc.yaml)
  - Plugin list: [dockers/jenkins/master/plugins.txt](dockers/jenkins/master/plugins.txt)

## Useful commands
- Build agents:
  docker compose -f dockers/agents-compose.yaml build
- Start Jenkins:
  docker compose -f dockers/jenkins-compose.yaml up -d --build
- Enter an agent container (for local debugging):
  docker exec -it ubuntu-agent /bin/bash
  docker exec -it rhel-agent /bin/bash

## Where to look
- Pipeline: [Jenkinsfile](Jenkinsfile)
- CLI logic & tests: [nids-config.py](nids-config.py)
- Packaging (DEB control): [dockers/ubuntu-agent/control](dockers/ubuntu-agent/control)
- Packaging (RPM spec): [dockers/alma-agent/nids-config.spec](dockers/alma-agent/nids-config.spec)