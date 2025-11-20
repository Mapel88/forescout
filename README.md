# NIDS Configuration Repo

Lightweight repository that builds and validates a small NIDS configuration CLI packaged as DEB/RPM,
and provides a local Jenkins instance for building/testing using Docker-based agents.

## Prerequisites
- Docker Desktop installed and running (with Docker Compose)
- git (for checking out repo)
- On agents / test hosts: python3, iproute2 (ip), procps (sysctl), PyYAML (packaged or pip install PyYAML)

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
- After building, the pipeline validates packages by installing and running the CLI and the validator.

## CLI tool
- Main script: [nids-config.py](nids-config.py)
  - Key classes: `NIDSConfig`, `NetworkInterface`
- Default config: `/etc/nids/config.yaml` (tool always uses this path)
- Supported CLI actions:
  - `--enable-ipv6` / `--disable-ipv6` — try to apply kernel IPv6 via sysctl; operation is required for configure-all
  - `--enable-ipv4` — marks ipv4_enabled and will attempt to bring non-loopback interfaces UP (no global IPv4 kernel toggle)
  - `--set-prom-ipv6` / `--set-prom-ipv4` — set promiscuous mode on active interfaces and record results in config
  - `--configure-all` — enable both IPv4 & IPv6 and set promiscuous mode on all active interfaces (will fail if kernel IPv6 sysctl cannot be applied)
  - `--status` — display configuration and interface/promisc status
  - `--validate` — run local environment checks
- Notes:
  - There is no single safe kernel toggle to globally disable IPv4; the tool does not attempt destructive global IPv4 kernel changes.
  - `configure-all` is strict: it will fail if kernel IPv6 cannot be applied (sysctl missing or permission denied).

## Validator
- Script: [validator.py](validator.py)
- Usage highlights (used by pipeline):
  - `python3 validator.py --expect-ipv6 true|false|skip --expect-ipv4 true|false|skip`
  - `--run-configure-all` — invoke `nids-config --configure-all` then validate config and promiscuous interfaces (validator treats failure as fatal)
- Validator behavior:
  - Always checks config keys in `/etc/nids/config.yaml`.
  - Validates kernel IPv6 state when requested — missing sysctl or permission errors are treated as failures to match nids-config strict behavior.
  - Promiscuous/interface checks require `ip` tool and NET_ADMIN capability in agents; otherwise tests may fail.

## Jenkins / Agent notes
- Agent images must include:
  - `iproute2` (`ip`), `procps` (`sysctl`), `python3`, and PyYAML (or installation via pip).
- Agent containers must run with sufficient capabilities to allow:
  - setting interface promisc: `NET_ADMIN`, `NET_RAW`
  - changing kernel sysctls (may require `SYS_ADMIN` or privileged container depending on host/seccomp/AppArmor)
- Prefer granting specific capabilities to Jenkins agent containers (cap_add) instead of `privileged: true` where possible.

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
- Validator: [validator.py](validator.py)
- Packaging (DEB control): [dockers/ubuntu-agent/control](dockers/ubuntu-agent/control)
- Packaging (RPM spec): [dockers/alma-agent/nids-config.spec](dockers/alma-agent/nids-config.spec)