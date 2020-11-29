FROM debian:10
LABEL maintainer="Federico Pereira <lord.basex@gmail.com>"
LABEL author="Fernando Romo <pop@cofradia.org>"

ENV SIPBAN_PORT=4451 \
    TZ='America/Mexico_City' \
    AMI_PING=600 \
    TIMER_BAN=86400 \ 
    IPTABLES_CHAIN='sipban-udp' \
    IPTABLES_RULE=REJECT

RUN apt update && apt-get -y install 
    git \
    libproc-pid-file-perl \
    libconfig-simple-perl \
    libtime-hires-perl \
    telnet \
    net-tools \
    iptables \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/elpop/sipban.git /usr/src/sipban \
    && mkdir -p /etc/sipban \ 
    && cd /usr/src/sipban \
    && cp sipban.pl /usr/local/bin \
    && cp etc/sipban.conf /etc/. \
    && cp etc/sipban.wl /etc/sipban/.  \
    && chmod +x /usr/local/bin/sipban.pl \
    && mkdir -p /var/log/sipban \
    && cp -fra /etc/sipban /etc/sipban.org \
    && rm -rf /usr/src/sipban

VOLUME [ "/etc/sipban" ,"/var/log/sipban" ]

COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

EXPOSE 4451

ENTRYPOINT ["/docker-entrypoint.sh"]
