FROM almalinux:9.4

RUN dnf -y update && dnf -y install \
    sudo nano wget git \
    python3 python3-pip \
    gcc make rpm-build rpmdevtools redhat-rpm-config \
    ruby rubygems openssh-server \
    java-17-openjdk-devel \
  && dnf clean all

# Configure SSH for Jenkins agent
RUN mkdir /var/run/sshd && \
    useradd -m jenkins && echo "jenkins:jenkins" | chpasswd && \
    usermod -aG wheel jenkins && \
    echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER jenkins
WORKDIR /jenkins-workspace
CMD ["/bin/bash"]
