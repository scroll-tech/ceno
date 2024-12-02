# This docker image is used to run the CI pipeline in the Github Actions

FROM ghcr.io/actions/actions-runner:latest

COPY start.sh start.sh
RUN sudo apt update && \
    sudo apt install -y --no-install-recommends \
    curl jq build-essential libssl-dev libffi-dev python3 python3-venv python3-dev python3-pip && \
    sudo ./bin/installdependencies.sh && \
    sudo chown runner:runner start.sh && \
    chmod +x start.sh

ENTRYPOINT ["./start.sh"]
