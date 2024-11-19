FROM ghcr.io/actions/actions-runner:latest

RUN sudo ./bin/installdependencies.sh
COPY start.sh start.sh
RUN sudo chown runner:runner start.sh && chmod +x start.sh

ENTRYPOINT ["./start.sh"]
