FROM jenkins/jenkins:lts-jdk17

USER root

# Install basic tools Jenkins pipelines might use
RUN apt-get update && apt-get install -y \
    git curl unzip \
    ca-certificates gnupg lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
 && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list \
 && apt-get update && apt-get install -y docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

# Copy plugin list and install them
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# Copy the JCasC configuration
COPY jenkins-casc.yaml /usr/share/jenkins/ref/casc.yaml
ENV CASC_JENKINS_CONFIG=/var/jenkins_home/casc.yaml


USER jenkins
