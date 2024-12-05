FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3.9 \
    python3.9-venv \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1
RUN update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip 1

WORKDIR /app/tool

COPY . /app

RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install --upgrade pip
RUN /app/venv/bin/pip install -r /app/requirements.txt

RUN /app/venv/bin/pyinstaller   \
        --collect-all z3        \
        --collect-all pyvex     \
        --collect-all angr      \
        --collect-all unicorn   \
        --collect-all cle       \
        --onefile --name capierre_binary /app/src/__main__.py

CMD ["bash"]
