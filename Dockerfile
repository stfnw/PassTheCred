# This Dockerfile only serves as example for how to build the project.
# If dependencies are installed a simple `make` without docker should suffice.

# git clone https://github.com/stfnw/PassTheCred
# cd PassTheCred
# podman build -t build-pass-the-cred .
# podman run --rm --network none --volume .:/data/ localhost/build-pass-the-cred

FROM docker.io/debian:bookworm

RUN apt-get -y update \
    && apt-get -y install \
        build-essential \
        mingw-w64 \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data/

ENTRYPOINT ["make"]
