FROM ubuntu:22.04

USER root
ENV DEBIAN_FRONTEND=noninteractive
ARG USER=jenkins
ARG UID=1000
ARG GID=1000

# Install packages for building .deb and Java
RUN apt-get update 
RUN apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    ca-certificates apt-transport-https gnupg lsb-release curl \
    build-essential ruby-full rubygems-integration \
    python3 python3-venv python3-pip sudo wget git dpkg-dev \
    pkg-config make file openssh-client openssh-server
RUN rm -rf /var/lib/apt/lists/*

# Install fpm (packaging tool)
RUN gem install --no-document fpm

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
