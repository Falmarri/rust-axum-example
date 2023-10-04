# Using the `rust-musl-builder` as base image, instead of
# the official Rust toolchain
FROM docker.io/rust:1-bookworm AS chef
USER root
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as planner-cli
COPY ./prisma-cli .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as builder-cli
COPY --from=planner /app/recipe.json recipe.json
# Notice that we are specifying the --target flag!
RUN cargo chef cook --recipe-path recipe.json
COPY ./prisma-cli .
RUN cargo build

FROM chef AS builder
RUN curl -sL -o tailwindcss https://github.com/tailwindlabs/tailwindcss/releases/download/v3.3.3/tailwindcss-linux-x64 \
    && chmod +x tailwindcss && mv tailwindcss /usr/local/bin
COPY --from=planner /app/recipe.json recipe.json
# Notice that we are specifying the --target flag!
RUN cargo chef cook --all-targets --recipe-path recipe.json
COPY --from=builder-cli /app/target/*/prisma-cli /usr/local/bin
RUN prisma-cli
COPY . .
RUN tailwindcss -i styles/tailwind.css -o assets/main.css
RUN sed -i "s;cargo prisma;prisma-cli;" prisma/schema.prisma
RUN prisma-cli generate

RUN cargo build

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y \
    openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/prisma-cli /usr/local/bin/
RUN prisma-cli
RUN useradd -m -s /bin/bash -U -u 1000 appuser
RUN mv /root/.cache /home/appuser/
COPY --from=builder /app/target/*/cryptcase /usr/local/bin/

COPY --from=builder /app/assets /app/assets
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/prisma /app/prisma
ENV ASSETS_PATH=/app/assets TEMPLATES_PATH=/app/templates
WORKDIR /app

USER appuser
CMD ["/usr/local/bin/cryptcase"]