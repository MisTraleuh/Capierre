FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

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
