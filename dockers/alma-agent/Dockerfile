FROM almalinux:9.4

USER root

# Define variables for user ID mapping (Default to common Linux UIDs/GIDs)
ARG USER=jenkins
ARG UID=1000
ARG GID=1000

# Install necessary packages
RUN dnf -y update && dnf -y install \
    sudo wget git java-17-openjdk-devel openssh-server \
    gcc make rpm-build rpmdevtools redhat-rpm-config \
    python3 python3-pip python3-pyyaml
    
RUN dnf clean all

# Configure SSH for Jenkins agent
RUN mkdir /var/run/sshd

# 1. Create a non-root group and user using the defined UID/GID ARGs
RUN groupadd --gid ${GID} ${USER} || true
RUN useradd --uid ${UID} --gid ${GID} -m -s /bin/bash ${USER} || true

# 2. Set password, add to wheel, and configure sudo
RUN echo "${USER}:${USER}" | chpasswd 
RUN usermod -aG wheel ${USER}
RUN echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set up Jenkins workspace
RUN mkdir -p /jenkins-workspace
# Set ownership using the variables
RUN chown "${UID}:${GID}" /jenkins-workspace
WORKDIR /jenkins-workspace
USER ${USER}

CMD ["/bin/bash"]
