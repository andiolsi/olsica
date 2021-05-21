
# Information
I needed a docker image to use for a kubernetes initContainer to generate certificates for an etcd deployment.

In that context the goal of this container is to take a CA cert and key via configMap, generate a client csr,key and cert and write everything to a mounted emptyDir: {}.

It can be of use to manage a "real" CA and at the very least could be a reference to some.

If specified, OLSICA_TARGET_CLIENT_KEYSTORE_FILENAME and OLSICA_TARGET_CLIENT_TRUSTSTORE_FILENAME will generate Java Key/Trustores.
If specified, OLSICA_TARGET_CLIENT_PKCS8_FILENAME will create PKCS8 version of the key.


I haven't done excessive testing, so some stuff may not work. 

Test via docker:
```
mkdir /tmp/certificates_ca
mkdir /tmp/certificates_out
openssl ecparam -out /tmp/certificates_ca/ca.key  -name prime256v1 -genkey
openssl req -new  -days 365 -nodes -x509 -key /tmp/certificates_ca/ca.key -out /tmp/certificates_ca/ca.crt -subj "/CN=olsica/"

docker run -it --rm  -v /tmp/certificates_ca:/certificates_ca  -v /tmp/certificates_out:/certificates_out  -e OLSICA_CLIENT_NAME="test" -e OLSICA_KEY_ALGORITHM=RSA -e OLSICA_CLIENT_SUBJECTALTNAMES="foo.com,*.foo.com,127.0.0.1"   -t andiolsi/olsica:latest
```


## debug mode
- OLSICA_DEBUG=${OLSICA_DEBUG:-}


# client name will automatically generate subject as /CN=client_name/, can be overridden
- OLSICA_CLIENT_NAME
- OLSICA_CLIENT_SUBJECT="${OLSICA_CLIENT_SUBJECT:-/CN=${OLSICA_CLIENT_NAME}/}"

## variables to control certificate validity
- OLSICA_CERTIFICATE_VALIDITY_DAYS=${OLSICA_CERTIFICATE_VALIDITY_DAYS:-7300}


## variables to control key generation algorithm
Supported key algorithms are RSA and EC.

- OLSICA_KEY_ALGORITHM=${OLSICA_KEY_ALGORITHM:-EC}
- OLSICA_ECPARAM=${OLSICA_ECPARAM:-prime256v1}
- OLSICA_RSA_BITS=${OLSICA_RSA_BITS:-4096}
- OLSICA_KEY_USAGE=${OLSICA_KEY_USAGE:-digitalSignature}
- OLSICA_EXTENDED_KEY_USAGE=${OLSICA_EXTENDED_KEY_USAGE:-clientAuth,serverAuth}


## variables for source file and directories
- OLSICA_SOURCE_DIRECTORY=${OLSICA_SOURCE_DIRECTORY:-/certificates_ca}
- OLSICA_SOURCE_CA_CERTIFICATE_FILENAME=${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME:-ca.crt}
- OLSICA_SOURCE_CA_KEY_FILENAME=${OLSICA_SOURCE_CA_KEY_FILENAME:-ca.key}
- OLSICA_SOURCE_CA_CONFIG_PATH=${OLSICA_SOURCE_CA_CONFIG_PATH:-}
- OLSICA_SOURCE_CA_SERIAL_PATH=${OLSICA_SOURCE_CA_SERIAL_PATH:-/tmp/ca.srl}
- OLSICA_SOURCE_CA_DATABASE_PATH=${OLSICA_SOURCE_CA_DATABASE_PATH:-/tmp/certificate.db}
- OLSICA_SOURCE_CA_SERIAL_MODE="${OLSICA_SOURCE_CA_SERIAL_MODE:-rand_serial}"
- OLSICA_SOURCE_CA_DIGEST="${OLSICA_SOURCE_CA_DIGEST:-sha256}"

## variables to control permissions on target files and directories
- OLSICA_TARGET_UID=${OLSICA_TARGET_UID:-1000}
- OLSICA_TARGET_GID=${OLSICA_TARGET_GID:-0}
- OLSICA_TARGET_MODE_CERTS=${OLSICA_TARGET_MODE_CERTS:-644}
- OLSICA_TARGET_MODE_KEY=${OLSICA_TARGET_MODE_KEY:-600}

## variables for certificate content
- OLSICA_CLIENT_SUBJECTALTNAMES=${OLSICA_CLIENT_SUBJECTALTNAMES:-}

## variables for target file and directories
- OLSICA_TARGET_DIRECTORY=${OLSICA_TARGET_DIRECTORY:-/certificates_out}
- OLSICA_TARGET_CA_CERTIFICATE_FILENAME=${OLSICA_TARGET_CA_CERTIFICATE_FILENAME:-ca.crt}
- OLSICA_TARGET_CLIENT_KEY_FILENAME=${OLSICA_TARGET_CLIENT_KEY_FILENAME:-client.key}
- OLSICA_TARGET_CLIENT_CSR_FILENAME=${OLSICA_TARGET_CLIENT_CERTIFICATE_REQUEST_FILENAME:-client.csr}
- OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME=${OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME:-client.crt}
- OLSICA_TARGET_CLIENT_PKCS12=${OLSICA_TARGET_CLIENT_PKCS12:-client.p12}
- OLSICA_TARGET_CLIENT_PKCS12_PASSWORD=${OLSICA_TARGET_CLIENT_PKCS12_PASSWORD:-client}
- OLSICA_TARGET_CLIENT_KEYSTORE_FILENAME=${OLSICA_TARGET_CLIENT_KEYSTORE_FILENAME:-}
- OLSICA_TARGET_CLIENT_KEYSTORE_PASSWORD=${OLSICA_TARGET_CLIENT_KEYSTORE_PASSWORD:-client}
- OLSICA_TARGET_CLIENT_TRUSTSTORE_FILENAME=${OLSICA_TARGET_CLIENT_TRUSTSTORE_FILENAME:-}
- OLSICA_TARGET_CLIENT_TRUSTSTORE_PASSWORD=${OLSICA_TARGET_CLIENT_TRUSTSTORE_PASSWORD:-client}
