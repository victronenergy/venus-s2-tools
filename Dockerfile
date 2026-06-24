FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        python3 \
        python3-pip \
        python3-venv \
        git \
        build-essential \
        qt6-base-dev \
        qt6-base-dev-tools \
        libncursesw5-dev \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

RUN git clone --depth 1 --recurse-submodules --branch master https://github.com/victronenergy/dbus-spy.git dbus-spy
WORKDIR /workspace/dbus-spy/software
RUN qmake6 && \
    make -j"$(nproc)"
RUN install -Dm755 ./dbus-spy /usr/local/bin/dbus-spy
WORKDIR /workspace

COPY *.py /workspace/
COPY requirements.txt /requirements.txt
COPY system.conf /etc/dbus-1/system.conf

RUN pip3 install --no-cache-dir --break-system-packages -r /requirements.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]