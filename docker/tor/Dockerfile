# Tor SOCKS gateway for the isolated dark-web research zone.
FROM alpine:3.20
RUN apk add --no-cache tor && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor
COPY torrc /etc/tor/torrc
USER tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
