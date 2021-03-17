FROM alpine:latest

WORKDIR /olsica

COPY scripts/* ./

ENTRYPOINT [ "/olsica/entrypoint.sh" ]
RUN apk add --update-cache bash openssl java-gcj-compat openjdk11 ca-certificates 
