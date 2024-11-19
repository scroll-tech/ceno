FROM ghcr.io/actions/actions-runner:latest

RUN sudo ./bin/installdependencies.sh
COPY start.sh start.sh
RUN chmod +x start.sh

ENTRYPOINT ["./start.sh"]
