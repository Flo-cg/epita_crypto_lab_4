# One small image for the three "machines" that run OpenSSL (root-ca, issuing-ca, client);
# age is there for keys.sh, which encrypts the identities' private keys before they are committed.
FROM alpine:3.23
RUN apk add --no-cache openssl curl age
WORKDIR /pki
