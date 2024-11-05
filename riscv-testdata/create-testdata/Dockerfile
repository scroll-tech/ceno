FROM --platform=linux/amd64 ubuntu:latest AS builder-stage

# Set the working directory
WORKDIR /root

# Install necessary tools to build RISC-V tests
RUN apt-get update && apt-get install --yes curl git autoconf g++ build-essential

# Download and extract RISC-V GNU toolchain binaries
RUN curl --fail --silent --show-error --location \
         https://github.com/riscv-collab/riscv-gnu-toolchain/releases/download/2023.07.05/riscv32-elf-ubuntu-22.04-gcc-nightly-2023.07.05-nightly.tar.gz \
         | tar --extract --gzip --verbose

# Set the environment variables
ENV PATH="/root/riscv/bin:${PATH}"
ENV RISCV="/root"

# Clone the RISC-V tests repository
# (Get only the specific commit we want)
## The ADD is to invalidate the Docker cache, if the repository changes.
## So that we get a fresh clone.
ADD https://api.github.com/repos/riscv/riscv-tests/git/refs/heads/master version.json
RUN git clone --depth=1 https://github.com/riscv/riscv-tests.git
WORKDIR /root/riscv-tests/

# Set the environment variable for the RISC-V tests
ENV RISCV_TEST="/root/riscv-tests/isa"

# Update tests
RUN git submodule update --init --depth=1 --recursive && \
    git rev-parse HEAD | tee .testdata_generated_from_this_commit

# Build the tests - we are interested in rv32ui and rv32um
# We want to add the CFLAGS "-save-temps -frandom-seed=1" to the build,
# but upstream forces us to repeat all their default flags here, too.
RUN autoconf && \
    ./configure --prefix=/root/riscv-tests && \
    cd isa && \
    make rv32ui rv32um XLEN=32 RISCV_GCC_OPTS="-save-temps -frandom-seed=1 -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles"

RUN rm -f /root/riscv-tests/isa/.gitignore

FROM scratch AS exporter-stage

# Copy all built tests to the host system
COPY --from=builder-stage /root/riscv-tests/isa /
COPY --from=builder-stage /root/riscv-tests/.testdata_generated_from_this_commit /
