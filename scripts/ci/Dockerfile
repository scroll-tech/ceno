# this dockerfile is borrowed from https://baccini-al.medium.com/how-to-containerize-a-github-actions-self-hosted-runner-5994cc08b9fb
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG RUNNER_VERSION="2.320.0"
ARG CHECKSUM="93ac1b7ce743ee85b5d386f5c1787385ef07b3d7c728ff66ce0d3813d5f46900"

RUN apt update -y && apt upgrade -y && useradd -m docker
RUN apt install -y --no-install-recommends \
    curl jq build-essential libssl-dev libffi-dev python3 python3-venv python3-dev python3-pip

# these are the dependencies of actions-runner
RUN apt install -y --no-install-recommends \
    libkrb5-3 zlib1g libicu70

RUN cd /home/docker && mkdir actions-runner && cd actions-runner \
    && curl -o actions-runner-linux-x64-$RUNNER_VERSION.tar.gz -L https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-x64-$RUNNER_VERSION.tar.gz \
    && echo "$CHECKSUM  actions-runner-linux-x64-$RUNNER_VERSION.tar.gz" | shasum -a 256 -c \
    && tar xzf ./actions-runner-linux-x64-$RUNNER_VERSION.tar.gz

RUN chown -R docker ~docker && cd /home/docker/actions-runner/bin/ \
    && chmod +x installdependencies.sh \
    && ./installdependencies.sh

COPY start.sh start.sh
RUN chmod +x start.sh

# GitHub action runner scripts (config.sh and run.sh) are not allowed to be run as root
USER docker

ENTRYPOINT ["./start.sh"]
