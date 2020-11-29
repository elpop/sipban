# DOCKER SIPban

## DOCKER RUN
```bash
docker run --privileged -itd --name sipban --net=host --env AMI_PORT=5038 --env AMI_USER=sipban --env AMI_PASS=getout --env AMI_HOST=localhost cnsoluciones/sipban
```

## TERMINAL
```bash
docker exec -it sipban telnet localhost 4451
```

## DOCKER COMPOSE

```bash
version: '3.3'
services:

  sipban:
    environment:
        - "AMI_PORT=5038"
        - "AMI_USER=sipban"
        - "AMI_PASS=getout"
        - "AMI_HOST=localhost"
        #optional
        - "TZ=America/Mexico_City"
        - "SIPBAN_PORT=4451"
        - "AMI_PING=600"
        - "TIMER_BAN=86400"
        - "IPTABLES_CHAIN=sipban-udp"
        - "IPTABLES_RULE=REJECT"
    privileged: true
    container_name: sipban
    image: cnsoluciones/sipban:latest
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - ./user-data/etc/sipban:/etc/sipban
      - ./user-data/logs/sipban:/var/log/sipban
    restart: always
    network_mode: host
```

## DOCKER COMPOSE UP
```bash
docker-compose up -d
```

## DOCKER COMPOSE DOWN
```bash
docker-compose down
```

## DOCKER COMPOSE TERMINAL
```bash
docker-compose exec sipban telnet localhost 4451
```

## DOCKER COMPOSE CLI
```bash
docker-compose exec sipban bash
```

