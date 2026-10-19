FROM alpine:3.21

RUN apk add --no-cache socat iptables tcpdump

CMD ["socat", "-d", "-d", \
     "TCP-LISTEN:5020,bind=0.0.0.0,reuseaddr,fork", \
     "TCP:172.28.20.10:5020"]
