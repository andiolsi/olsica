#!/usr/bin/env bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# this script will use an existing CA to create a client key, signing request and signed certificate


_errs=0

_supported_algorithms=("EC" "RSA")


OLSICA_NAME=${OLSICA_NAME:-olsica}

# debug mode
OLSICA_DEBUG=${OLSICA_DEBUG:-}

# variables to control certificate validity
OLSICA_CERTIFICATE_VALIDITY_DAYS=${OLSICA_CERTIFICATE_VALIDITY_DAYS:-7300}


[ ! -z "${OLSICA_DEBUG}" ] && set -x
# variables to control key generation algorithm
OLSICA_KEY_ALGORITHM=${OLSICA_KEY_ALGORITHM:-EC}
OLSICA_ECPARAM=${OLSICA_ECPARAM:-prime256v1}
OLSICA_RSA_BITS=${OLSICA_RSA_BITS:-4096}
OLSICA_KEY_USAGE=${OLSICA_KEY_USAGE:-digitalSignature}
OLSICA_EXTENDED_KEY_USAGE=${OLSICA_EXTENDED_KEY_USAGE:-clientAuth,serverAuth}

# variables for source file and directories
OLSICA_SOURCE_DIRECTORY=${OLSICA_SOURCE_DIRECTORY:-/certificates_ca}
OLSICA_SOURCE_CA_CERTIFICATE_FILENAME=${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME:-ca.crt}
OLSICA_SOURCE_CA_KEY_FILENAME=${OLSICA_SOURCE_CA_KEY_FILENAME:-ca.key}
OLSICA_SOURCE_CA_CONFIG_PATH=${OLSICA_SOURCE_CA_CONFIG_PATH:-}
OLSICA_SOURCE_CA_SERIAL_PATH=${OLSICA_SOURCE_CA_SERIAL_PATH:-/tmp/ca.srl}
OLSICA_SOURCE_CA_DATABASE_PATH=${OLSICA_SOURCE_CA_DATABASE_PATH:-/tmp/certificate.db}
OLSICA_SOURCE_CA_SERIAL_MODE="${OLSICA_SOURCE_CA_SERIAL_MODE:-rand_serial}"
OLSICA_SOURCE_CA_DIGEST="${OLSICA_SOURCE_CA_DIGEST:-sha256}"

# variables to control permissions on target files and directories
OLSICA_TARGET_UID=${OLSICA_TARGET_UID:-1000}
OLSICA_TARGET_GID=${OLSICA_TARGET_GID:-0}
OLSICA_TARGET_MODE_CERTS=${OLSICA_TARGET_MODE_CERTS:-644}
OLSICA_TARGET_MODE_KEY=${OLSICA_TARGET_MODE_KEY:-600}

# variables for certificate content
OLSICA_CLIENT_SUBJECTALTNAMES=${OLSICA_CLIENT_SUBJECTALTNAMES:-}

# variables for target file and directories
OLSICA_TARGET_DIRECTORY=${OLSICA_TARGET_DIRECTORY:-/certificates_out}
OLSICA_TARGET_CA_CERTIFICATE_FILENAME=${OLSICA_TARGET_CA_CERTIFICATE_FILENAME:-ca.crt}
OLSICA_TARGET_CLIENT_KEY_FILENAME=${OLSICA_TARGET_CLIENT_KEY_FILENAME:-client.key}
OLSICA_TARGET_CLIENT_CSR_FILENAME=${OLSICA_TARGET_CLIENT_CERTIFICATE_REQUEST_FILENAME:-client.csr}
OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME=${OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME:-client.crt}
OLSICA_TARGET_CLIENT_PKCS8_FILENAME=${OLSICA_TARGET_CLIENT_PKCS8_FILENAME:-client.pkcs8}
OLSICA_TARGET_CLIENT_PKCS12=${OLSICA_TARGET_CLIENT_PKCS12:-client.p12}
OLSICA_TARGET_CLIENT_PKCS12_PASSWORD=${OLSICA_TARGET_CLIENT_PKCS12_PASSWORD:-client}
OLSICA_TARGET_CLIENT_KEYSTORE_FILENAME=${OLSICA_TARGET_CLIENT_KEYSTORE_FILENAME:-}
OLSICA_TARGET_CLIENT_KEYSTORE_PASSWORD=${OLSICA_TARGET_CLIENT_KEYSTORE_PASSWORD:-client}
OLSICA_TARGET_CLIENT_TRUSTSTORE_FILENAME=${OLSICA_TARGET_CLIENT_TRUSTSTORE_FILENAME:-}
OLSICA_TARGET_CLIENT_TRUSTSTORE_PASSWORD=${OLSICA_TARGET_CLIENT_TRUSTSTORE_PASSWORD:-client}

###########################
###   PREFLIGHT CHECKS ####
###########################

echo "running preflight checks"
if [ ! -d "${OLSICA_SOURCE_DIRECTORY}" ]
then
    echo "source directory ${OLSICA_SOURCE_DIRECTORY} does not exist (check variable: OLSICA_SOURCE_DIRECTORY)"
    let _errs++
else
    echo "source directory is ${OLSICA_SOURCE_DIRECTORY}"
    if [ ! -f "${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_KEY_FILENAME}" ]
    then
        echo "no CA key file found at '${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_KEY_FILENAME}' (check variable: OLSICA_SOURCE_CA_KEY_FILENAME, it defaults to 'ca.crt')"
        let _errs++
    fi
    if [ ! -f "${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME}" ]
    then
        echo "no CA certificate file found at '${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME}'  (check variable: OLSICA_SOURCE_CA_CERTIFICATE_FILENAME, it defaults to 'ca.key')"
        let _errs++
    fi
fi

if [ ! -d "${OLSICA_TARGET_DIRECTORY}" ]
then
    echo "target directory ${OLSICA_TARGET_DIRECTORY} does not exist (check variable: OLSICA_TARGET_DIRECTORY)"
    let _errs++
else
    echo "target directory is ${OLSICA_TARGET_DIRECTORY}"
    if [ ! -w "${OLSICA_TARGET_DIRECTORY}" ]
    then
        echo "target ${OLSICA_TARGET_DIRECTORY} is not writable"
        let _errs++
    fi
fi

if [ -z "${OLSICA_CLIENT_NAME}" ]
then
    echo "client name is empty or unspecified (check variable: OLSICA_CLIENT_NAME)"
    let _errs++
else
    OLSICA_CLIENT_SUBJECT="${OLSICA_CLIENT_SUBJECT:-/CN=${OLSICA_CLIENT_NAME}/}"
fi

printf '%s\n' "${_supported_algorithms[@]}" | egrep -q "^${OLSICA_KEY_ALGORITHM}$"
if [ $? -ne 0 ]
then
    echo "the configured key algoritm ${OLSICA_KEY_ALGORITHM} is not supported by this script (chech variable: OLSICA_KEY_ALGORITHM)"
    echo "supported variables:"
    printf -- '- %s\n' "${_supported_algorithms[@]}"
    let _errs++
fi

if [ ${_errs} -ne 0 ]
then
    echo "encountered ${_errs} errors during preflight check, please check above output for error messages"
    exit 1
fi



[ ! -z "${OLSICA_DEBUG}" ] && ls -la "${OLSICA_SOURCE_DIRECTORY}"
[ ! -z "${OLSICA_DEBUG}" ] && ls -la "${OLSICA_TARGET_DIRECTORY}"


#################################
### subjectAltName generator ####
#################################

[ ! -z "${OLSICA_DEBUG}" ] && ip addr show dev eth0
_ipv4addr="`ip addr show dev eth0 |grep inet |grep -v inet6 |xargs -I INETADDR bash -c \"echo INETADDR | awk -F '[ /]' '{print \\\$2}'\"`"
_ipv6addr="`ip addr show dev eth0 |grep inet6 |xargs -I INETADDR bash -c \"echo INETADDR | awk -F '[ /]' '{print \\\$2}'\"`"


_subjectAltName="IP:127.0.0.1"
if [ ! -z "${_ipv4addr}" ] && [ ! -z "${_ipv6addr}" ]
then
    _subjectAltName="${_subjectAltName},IP:${_ipv4addr},IP:${_ipv6addr}"
else
    if [ ! -z "${_ipv4addr}" ] && [ -z "${_ipv6addr}" ]
    then
        _subjectAltName="${_subjectAltName},IP:${_ipv4addr}"
    else
        _subjectAltName="${_subjectAltName},IP:${_ipv6addr}"
    fi
fi
declare -a _client_altnames

if [ ! -z "${OLSICA_CLIENT_SUBJECTALTNAMES}" ]
then
    echo "process subjectAltNames"
    readarray -td, _client_altnames <<<"${OLSICA_CLIENT_SUBJECTALTNAMES},"; unset '_client_altnames[-1]'



    for _altname in "${_client_altnames[@]}"
    do
        [ ! -z "${OLSICA_DEBUG}" ] && echo "processing altname: '${_altname}'"
        echo -n "${_altname}" | grep -qoE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
        if [ $? -eq 0 ]
        then
            [ ! -z "${OLSICA_DEBUG}" ] && echo "${_altname} is an ip address, prepending 'IP:'"
            _subjectAltName="${_subjectAltName},IP:${_altname}"
        else
            [ ! -z "${OLSICA_DEBUG}" ] && echo "${_altname} is not an ip adress, prepending 'DNS:'"
            _subjectAltName="${_subjectAltName},DNS:${_altname}"
        fi
    done
else
    [ ! -z "${OLSICA_DEBUG}" ] && echo "no subjectAltNames specifed (variable: OLSICA_CLIENT_SUBJECTALTNAMES)"
fi


# from here lets not have any errors
set -e


##############################
###  client key generation ###
##############################

echo "generate client key"
if [ "${OLSICA_KEY_ALGORITHM}" == "EC" ]
then
    openssl ecparam -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}" -name "${OLSICA_ECPARAM}" -genkey
else
    openssl genrsa -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}" ${OLSICA_RSA_BITS} 
fi


###################################
###  client certificate request ###
##################################
echo "request certificate"

if [ ! -z "${_subjectAltName}" ]
then
    [ ! -z "${OLSICA_DEBUG}" ] && echo "requesting with subjectAltName=${_subjectAltName}"
    openssl req -subj "${OLSICA_CLIENT_SUBJECT}" \
     -key "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}" \
     -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CSR_FILENAME}" \
     -addext "subjectAltName=${_subjectAltName}" \
     -new
else
    openssl req -subj "${OLSICA_CLIENT_SUBJECT}" \
     -key "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}" \
     -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CSR_FILENAME}" \
     -new
fi





# create emty certificate database or harmlessly touch it
touch "${OLSICA_SOURCE_CA_DATABASE_PATH}"

echo "sign certificate request"
if [ ! -z "${OLSICA_SOURCE_CA_CONFIG_PATH}" ]
then
    openssl ca -days "${OLSICA_CERTIFICATE_VALIDITY_DAYS}" \
     -in "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CSR_FILENAME}" \
     -cert "${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME}" \
     -keyfile "${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_KEY_FILENAME}" \
     -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME}" \
     -notext \
     -${OLSICA_SOURCE_CA_SERIAL_MODE} \
     -md ${OLSICA_SOURCE_CA_DIGEST} \
     -batch\
     -config "${OLSICA_SOURCE_CA_CONFIG_PATH}" $@
else
    openssl ca -days "${OLSICA_CERTIFICATE_VALIDITY_DAYS}" \
     -in "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CSR_FILENAME}" \
     -cert "${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME}" \
     -keyfile "${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_KEY_FILENAME}" \
     -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME}" \
     -notext \
     -${OLSICA_SOURCE_CA_SERIAL_MODE} \
     -md ${OLSICA_SOURCE_CA_DIGEST} \
     -extensions ext \
     -batch\
     -config <( \
       echo '[ca]'; \
       echo 'default_ca=CA_default'; \
       echo '[CA_default]'; \
       echo "new_certs_dir=${OLSICA_TARGET_DIRECTORY}"; \
       echo "certificate=${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME}"; \
       echo "private_key=${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_KEY_FILENAME}"; \
       echo "dir=${OLSICA_SOURCE_DIRECTORY}"; \
       echo "certs=${OLSICA_TARGET_DIRECTORY}"; \
       echo "database=${OLSICA_SOURCE_CA_DATABASE_PATH}"; \
       echo "serial=${OLSICA_SOURCE_CA_SERIAL_PATH}"; \
       echo "policy=policy_match"; \
       echo "copy_extensions=copy"; \
       echo '[policy_match]'; \
       echo 'commonName=supplied'; \
       echo '[req]'; \
       echo 'distinguished_name=req'; \
       echo 'x509_extensions=ext'; \
       echo '[ext]'; \
       echo 'basicConstraints=CA:FALSE'; \
       echo "keyUsage=${OLSICA_KEY_USAGE}"; \
       echo "extendedKeyUsage=${OLSICA_EXTENDED_KEY_USAGE}";) $@
       
fi

echo "copying CA cert"
cp "${OLSICA_SOURCE_DIRECTORY}/${OLSICA_SOURCE_CA_CERTIFICATE_FILENAME}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CA_CERTIFICATE_FILENAME}"

echo "setting privleges on certificates to ${OLSICA_TARGET_MODE_CERTS}"
chmod "${OLSICA_TARGET_MODE_CERTS}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CA_CERTIFICATE_FILENAME}"
chmod "${OLSICA_TARGET_MODE_CERTS}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME}"
chmod "${OLSICA_TARGET_MODE_CERTS}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CSR_FILENAME}"
echo "setting privleges on key to ${OLSICA_TARGET_MODE_KEY}"
chmod "${OLSICA_TARGET_MODE_KEY}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}"

echo "setting ownership on certificates and key to ${OLSICA_TARGET_UID}:${OLSICA_TARGET_GID}"
chown "${OLSICA_TARGET_UID}:${OLSICA_TARGET_GID}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CA_CERTIFICATE_FILENAME}"
chown "${OLSICA_TARGET_UID}:${OLSICA_TARGET_GID}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME}"
chown "${OLSICA_TARGET_UID}:${OLSICA_TARGET_GID}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CSR_FILENAME}"
chown "${OLSICA_TARGET_UID}:${OLSICA_TARGET_GID}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}"



echo "generating pkcs12"
cat "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_CERTIFICATE_FILENAME}" "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CA_CERTIFICATE_FILENAME}" > /tmp/ssl-all.pem
openssl pkcs12 -export -name "${OLSICA_CLIENT_NAME}" -in /tmp/ssl-all.pem -inkey "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}" -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_PKCS12}" -passout pass:"${OLSICA_TARGET_CLIENT_PKCS12_PASSWORD}"

if [ ! -z "${OLSICA_TARGET_CLIENT_PKCS8_FILENAME}" ]
then
    echo "generating pkcs8"
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEY_FILENAME}" -out "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_PKCS8_FILENAME}"    
fi
if [ ! -z "${OLSICA_TARGET_CLIENT_KEYSTORE_FILENAME}" ]
then
    echo "generating keystore"
    keytool -importkeystore -destkeystore "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_KEYSTORE_FILENAME}" -srckeystore "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_PKCS12}" -srcstoretype pkcs12 -alias "${OLSICA_CLIENT_NAME}" -srcstorepass "${OLSICA_TARGET_CLIENT_PKCS12_PASSWORD}" -deststorepass "${OLSICA_TARGET_CLIENT_KEYSTORE_PASSWORD}" -noprompt
fi
if [ ! -z "${OLSICA_TARGET_CLIENT_TRUSTSTORE_FILENAME}" ]
then
    echo "generating truststore"
    set +e
    keytool -importcert -file "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CA_CERTIFICATE_FILENAME}" -alias "${OLSICA_NAME}" -trustcacerts -keystore "${OLSICA_TARGET_DIRECTORY}/${OLSICA_TARGET_CLIENT_TRUSTSTORE_FILENAME}" -storetype JKS -storepass "${OLSICA_TARGET_CLIENT_TRUSTSTORE_PASSWORD}" -noprompt
fi


echo "all operations completed successfully"

exit 0
