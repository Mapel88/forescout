FROM ubuntu:22.04

USER root
ENV DEBIAN_FRONTEND=noninteractive
ARG USER=jenkins
ARG UID=1000
ARG GID=1000

# Install packages for building .deb and Java
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    ca-certificates curl \
    build-essential pkg-config file dpkg-dev \
    python3 python3-venv python3-pip python3-yaml \
    sudo git openssh-client iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to match host UID
RUN groupadd --gid ${GID} ${USER} || true \
  && useradd --uid ${UID} --gid ${GID} -m -s /bin/bash ${USER} || true \
  && echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER} \
  && chmod 0440 /etc/sudoers.d/${USER}

# Set up Jenkins workspace
RUN mkdir -p /jenkins-workspace
RUN chown ${UID}:${GID} /jenkins-workspace
WORKDIR /jenkins-workspace
USER ${USER}
# ENV PATH="/home/${USER}/.local/bin:${PATH}"

CMD ["/bin/bash"]
