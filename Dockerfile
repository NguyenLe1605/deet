FROM rust:1.67

# Make .cargo writable by any user (so we can run the container as an
# unprivileged user)
RUN mkdir /.cargo && chmod 777 /.cargo

WORKDIR /deet
