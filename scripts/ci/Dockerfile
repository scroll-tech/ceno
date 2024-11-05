# this dockerfile is adapted from https://baccini-al.medium.com/how-to-containerize-a-github-actions-self-hosted-runner-5994cc08b9fb
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG RUNNER_VERSION="2.320.0"
ARG CHECKSUM="93ac1b7ce743ee85b5d386f5c1787385ef07b3d7c728ff66ce0d3813d5f46900"

RUN useradd --create-home docker

RUN apt update --yes && apt upgrade --yes && \
    apt install --yes --no-install-recommends \
    curl jq build-essential libssl-dev libffi-dev python3 python3-venv python3-dev python3-pip

# the dependencies of GitHub's actions-runner
RUN apt install --yes --no-install-recommends \
    libkrb5-3 zlib1g libicu70

WORKDIR /home/docker/actions-runner
RUN curl --output actions-runner.tar.gz --location https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-x64-$RUNNER_VERSION.tar.gz \
    && echo "$CHECKSUM actions-runner.tar.gz" | shasum --algorithm 256 --check \
    && tar xzf actions-runner.tar.gz \
    && rm actions-runner.tar.gz

WORKDIR /home/docker/actions-runner/bin/

# RUN chmod +x installdependencies.sh \
#     && ./installdependencies.sh

# COPY start.sh start.sh
# RUN chmod +x start.sh

# GitHub action runner scripts (config.sh and run.sh) are not allowed to be run as root
USER docker

# ENTRYPOINT ["./start.sh"]
