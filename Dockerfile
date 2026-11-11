# syntax=docker/dockerfile:1
# ==============================================================================
# Tradecraft Multi-Stage Container Build
#
# Targets:
#   1. slim  (~1.2 GB) : Core + 68 pure-Python tools + Go recon/web scanners + nmap + sqlmap
#                        docker build --target slim -t tradecraft:slim .
#   2. web   (~2.8 GB) : Default `web` profile (adds Chromium/Playwright, GoWitness, PHP/phpggc,
#                        Java/ysoserial, Ruby/WhatWeb/WPScan, Node/retire, searchsploit, kiterunner)
#                        docker build --target web -t tradecraft:web .
#   3. full  (~3.8 GB) : All 132 tools across `web`, `ad-network`, `cloud`, and `kubernetes`
#                        docker build --target full -t tradecraft:full .
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 0: Go Binary Builder (kept out of runtime images to save ~800 MB)
# ------------------------------------------------------------------------------
FROM golang:bookworm AS go-builder

ENV CGO_ENABLED=1 \
    GOPATH=/go \
    GOBIN=/out/bin \
    GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    git \
    ca-certificates \
    curl \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /out/bin

# Core Go recon & web scanners
RUN go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -ldflags="-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    mv /out/bin/httpx /out/bin/pd-httpx && \
    go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -ldflags="-s -w" github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -ldflags="-s -w" github.com/ffuf/ffuf/v2@latest && \
    go install -ldflags="-s -w" github.com/hahwul/dalfox/v2@latest && \
    go install -ldflags="-s -w" github.com/lc/gau/v2/cmd/gau@latest && \
    go install -ldflags="-s -w" github.com/lc/subjs@latest && \
    go install -ldflags="-s -w" github.com/PentestPad/subzy@latest && \
    go install -ldflags="-s -w" github.com/glebarez/cero@latest && \
    go install -ldflags="-s -w" github.com/rverton/webanalyze/cmd/webanalyze@latest && \
    go install -ldflags="-s -w" github.com/sensepost/gowitness@latest && \
    go install -ldflags="-s -w" github.com/ropnop/kerbrute@latest && \
    go install -ldflags="-s -w" github.com/owasp-amass/amass/v4/...@master

# TruffleHog & Trivy pre-built release binaries
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /out/bin && \
    curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /out/bin

# Kiterunner (kr) & Cloudfox pre-built release binaries
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then KR_ARCH="arm64"; CF_ARCH="arm64"; else KR_ARCH="amd64"; CF_ARCH="amd64"; fi && \
    curl -sSfL "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_${KR_ARCH}.tar.gz" -o /tmp/kr.tar.gz && \
    tar -xzf /tmp/kr.tar.gz -C /out/bin kr && \
    rm -f /tmp/kr.tar.gz && \
    curl -sSfL "https://github.com/BishopFox/cloudfox/releases/download/v1.14.0/cloudfox-linux-${CF_ARCH}.zip" -o /tmp/cloudfox.zip && \
    unzip -q /tmp/cloudfox.zip -d /tmp && \
    mv /tmp/cloudfox/cloudfox /out/bin/cloudfox && \
    chmod +x /out/bin/cloudfox && \
    rm -rf /tmp/cloudfox*

RUN strip --strip-unneeded /out/bin/* 2>/dev/null || true


# ------------------------------------------------------------------------------
# Stage 1: `slim` — Core + 68 Pure-Python Tools + Go Scanners + Nmap + SQLMap
# ------------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRADECRAFT_HOME=/root/.tradecraft \
    PATH="/root/.local/bin:/usr/local/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    git \
    libpcap0.8 \
    nmap \
    openssl \
    openssh-client \
    bsdmainutils \
    procps \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

# Copy core Go scanners from builder
COPY --from=go-builder /out/bin/subfinder \
                       /out/bin/dnsx \
                       /out/bin/pd-httpx \
                       /out/bin/katana \
                       /out/bin/nuclei \
                       /out/bin/interactsh-client \
                       /out/bin/ffuf \
                       /out/bin/dalfox \
                       /out/bin/gau \
                       /out/bin/subjs \
                       /out/bin/subzy \
                       /out/bin/cero \
                       /out/bin/webanalyze \
                       /out/bin/trufflehog \
                       /usr/local/bin/

# Pre-bake webanalyze technologies definition & CISA KEV catalog
RUN mkdir -p /opt/webanalyze && \
    curl -sSfL "https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json" \
      -o /opt/webanalyze/technologies.json || true && \
    mkdir -p /opt/cisa && \
    curl -sSfL "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
      -o /opt/cisa/kev.json || true

# Install testssl.sh
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh && \
    rm -rf /opt/testssl.sh/.git && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl

# Install lightweight Python CLI scanners
RUN pip install --no-cache-dir \
    sqlmap \
    arjun \
    wafw00f \
    git-dumper

WORKDIR /app
COPY pyproject.toml README.md ./
COPY tradecraft ./tradecraft
COPY config ./config
COPY scripts ./scripts

RUN pip install --no-cache-dir -e . && \
    mkdir -p /root/.tradecraft

VOLUME ["/root/.tradecraft"]
ENTRYPOINT ["tradecraft"]
CMD ["--help"]


# ------------------------------------------------------------------------------
# Stage 2: `web` — Default `web` Profile (Browser + Multi-Runtime Web Stack)
# ------------------------------------------------------------------------------
FROM slim AS web

# Install Chromium (shared by Playwright, GoWitness, and Katana), PHP, Java JRE, Ruby, Node, unzip
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation \
    libnss3 \
    libxss1 \
    libasound2 \
    libatomic1 \
    php-cli \
    openjdk-17-jre-headless \
    ruby \
    ruby-dev \
    build-essential \
    libcurl4-openssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    nodejs \
    npm \
    unzip \
    hydra \
    cewl \
    && gem install --no-document wpscan addressable && \
    npm install -g retire && \
    npm cache clean --force && \
    apt-get purge -y --auto-remove build-essential ruby-dev libcurl4-openssl-dev libxml2-dev libxslt1-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy GoWitness, Amass, and Kiterunner from go-builder
COPY --from=go-builder /out/bin/gowitness \
                       /out/bin/amass \
                       /out/bin/kr \
                       /usr/local/bin/

# Install Playwright Python driver & clairvoyance
RUN pip install --no-cache-dir playwright clairvoyance && \
    playwright install chromium

# Install WhatWeb, phpggc, SSTImap (tplmap compatible), LinkFinder, GitDorker, Corsy, Cloudfail, Commix
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    rm -rf /opt/whatweb/.git && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc && \
    rm -rf /opt/phpggc/.git && ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc && \
    git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/SSTImap && \
    rm -rf /opt/SSTImap/.git && \
    mkdir -p /opt/tplmap && \
    ln -s /opt/SSTImap/sstimap.py /opt/tplmap/tplmap.py && \
    ln -s /opt/SSTImap/sstimap.py /opt/tplmap/sstimap.py && \
    pip install --no-cache-dir -r /opt/SSTImap/requirements.txt && \
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder && \
    rm -rf /opt/LinkFinder/.git && pip install --no-cache-dir jsbeautifier && \
    git clone --depth 1 https://github.com/obheda12/GitDorker.git /opt/gitdorker && \
    rm -rf /opt/gitdorker/.git && pip install --no-cache-dir -r /opt/gitdorker/requirements.txt && \
    git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/corsy && \
    rm -rf /opt/corsy/.git && pip install --no-cache-dir -r /opt/corsy/requirements.txt && \
    printf '#!/bin/sh\nexec python3 /opt/corsy/corsy.py "$@"\n' > /usr/local/bin/corsy && chmod +x /usr/local/bin/corsy && \
    git clone --depth 1 https://github.com/m0rtem/CloudFail.git /opt/cloudfail && \
    rm -rf /opt/cloudfail/.git && \
    pip install --no-cache-dir -r /opt/cloudfail/requirements.txt && \
    if [ -f /opt/cloudfail/data/subdomains.txt ]; then head -n 100 /opt/cloudfail/data/subdomains.txt > /opt/cloudfail/data/subdomains_top100.txt; fi && \
    printf '#!/bin/sh\ncd /opt/cloudfail && exec python3 /opt/cloudfail/cloudfail.py "$@"\n' > /usr/local/bin/cloudfail && chmod +x /usr/local/bin/cloudfail && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    rm -rf /opt/jwt_tool/.git && pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt && \
    ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool && \
    git clone --depth 1 https://github.com/defparam/smuggler.git /opt/smuggler && \
    rm -rf /opt/smuggler/.git && ln -s /opt/smuggler/smuggler.py /usr/local/bin/smuggler && \
    git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix && \
    rm -rf /opt/commix/.git && ln -s /opt/commix/commix.py /usr/local/bin/commix && \
    git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK.git /opt/cmseek && \
    rm -rf /opt/cmseek/.git && \
    printf '#!/bin/sh\nexec python3 /opt/cmseek/cmseek.py "$@"\n' > /usr/local/bin/cmseek && chmod +x /usr/local/bin/cmseek && \
    git clone --depth 1 https://github.com/Mebus/cupp.git /opt/cupp && \
    rm -rf /opt/cupp/.git && chmod +x /opt/cupp/cupp.py && ln -s /opt/cupp/cupp.py /usr/local/bin/cupp.py

# Install stripped ExploitDB (`searchsploit`) — removes .git and papers/ to save ~850 MB
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    rm -rf /opt/exploitdb/.git /opt/exploitdb/papers && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Download ysoserial JAR for deserialization_probe
RUN mkdir -p /opt/ysoserial && \
    curl -sSfL https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar \
      -o /opt/ysoserial/ysoserial.jar

# Install web profile cloud enumeration tools (cloud_enum, pacu, scoutsuite) & ghauri
RUN pip install --no-cache-dir \
    git+https://github.com/initstring/cloud_enum.git \
    pacu \
    scoutsuite \
    git+https://github.com/r0oth3x49/ghauri.git


# ------------------------------------------------------------------------------
# Stage 3: `full` — Complete Suite (`web` + `ad-network` + `cloud` + `kubernetes`)
# ------------------------------------------------------------------------------
FROM web AS full

COPY --from=go-builder /out/bin/kerbrute \
                       /out/bin/trivy \
                       /out/bin/cloudfox \
                       /usr/local/bin/

# Install kubectl (static release binary)
RUN ARCH=$(dpkg --print-architecture) && \
    KUBE_VER=$(curl -L -s https://dl.k8s.io/release/stable.txt) && \
    curl -sSfL "https://dl.k8s.io/release/${KUBE_VER}/bin/linux/${ARCH}/kubectl" -o /usr/local/bin/kubectl && \
    chmod +x /usr/local/bin/kubectl

# Install Active Directory, Cloud, and Kubernetes Python tool suites
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir pipx && \
    pipx install impacket && \
    pipx install bloodhound && \
    pipx install certipy-ad && \
    pipx install powerview && \
    pipx install coercer && \
    pipx install kube-hunter && \
    pipx install git+https://github.com/Pennyw0rth/NetExec

# Download ysoserial.net release for deserialization_probe_dotnet
RUN mkdir -p /opt/ysoserial.net && \
    curl -sSfL https://github.com/pwntester/ysoserial.net/releases/download/v1.36/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip -o /tmp/ysonet.zip && \
    unzip -q /tmp/ysonet.zip -d /tmp/ysonet && \
    mv /tmp/ysonet/Release/* /opt/ysoserial.net/ && \
    rm -rf /tmp/ysonet*

ENTRYPOINT ["tradecraft"]
CMD ["--help"]
