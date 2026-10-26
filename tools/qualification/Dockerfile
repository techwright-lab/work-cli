FROM rust:1.98.1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl make gcc libc6-dev libssl-dev libcurl4-openssl-dev \
    zlib1g-dev python3 pkg-config xz-utils perl && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends libexpat1-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --output /tmp/git.tar.xz \
      https://www.kernel.org/pub/software/scm/git/git-2.55.0.tar.xz \
    && echo '457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357  /tmp/git.tar.xz' | sha256sum -c - \
    && mkdir /tmp/git-source \
    && tar -xJf /tmp/git.tar.xz -C /tmp/git-source --strip-components=1 \
    && make -C /tmp/git-source -j4 prefix=/usr NO_GETTEXT=YesPlease NO_TCLTK=YesPlease install \
    && rm -rf /tmp/git-source /tmp/git.tar.xz
RUN rustup component add rustfmt clippy
WORKDIR /workspace
