FROM debian:10
LABEL maintainer="Federico Pereira <lord.basex@gmail.com>"

ENV SIPBANPORT=4451 \
    TZ='America/Mexico_City'


RUN apt update && apt-get -y install git libproc-pid-file-perl libconfig-simple-perl libtime-hires-perl telnet net-tools iptables

RUN git clone https://github.com/elpop/sipban.git /usr/src/sipban \
    && cd /usr/src/sipban \
    && cp sipban.pl /usr/local/bin \
    && cp etc/sipban.conf /etc/. \
    && cp etc/sipban.wl /etc/.  \
    && chmod +x /usr/local/bin/sipban.pl \
    && mkdir -p /var/log/sipban

VOLUME [ "/var/log/sipban" ]

#RUN DOCKER SCRIPT
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

EXPOSE 4451

ENTRYPOINT ["/docker-entrypoint.sh"]