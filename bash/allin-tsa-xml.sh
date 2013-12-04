#!/bin/sh
# allin-tsa-xml.sh - 1.0
#
# Generic script using curl to invoke Swisscom Allin service: TSA
# Dependencies: curl, openssl, base64, sed, date, xmllint, tr
#
# Change Log:
#  1.0 04.12.2013: Initial version

######################################################################
# User configurable options
######################################################################

# AP_ID used to identify to Allin (provided by Swisscom)
AP_ID=cartel.ch

######################################################################
# There should be no need to change anything below
######################################################################

# Error function
error()
{
  [ "$VERBOSE" = "1" ] && echo "$@" >&2         # Verbose details
  exit 1                                        # Exit
}

# Check command line
DEBUG=
VERBOSE=
ENCRYPT=
while getopts "dv" opt; do                      # Parse the options
  case $opt in
    d) DEBUG=1 ;;                               # Debug
    v) VERBOSE=1 ;;                             # Verbose
  esac
done
shift $((OPTIND-1))                             # Remove the options

if [ $# -lt 3 ]; then                           # Parse the rest of the arguments
  echo "Usage: $0 <args> type hash"
  echo "  -v       - verbose output"
  echo "  -d       - debug mode"
  echo "  digest   - digest/hash to be signed"
  echo "  method   - digest method (SHA224, SHA256, SHA384, SHA512)"
  echo "  pkcs7    - output file with PKCS#7 (Crytographic Message Syntax)"
  echo
  echo "  Example $0 -v GcXfOzOP8GsBu7odeT1w3GnMedppEWvngCQ7Ef1IBMA= SHA256 result.p7s"
  echo 
  exit 1
fi

PWD=$(dirname $0)                               # Get the Path of the script

# Check the dependencies
for cmd in curl openssl base64 sed date xmllint tr; do
  hash $cmd &> /dev/null
  if [ $? -eq 1 ]; then error "Dependency error: '$cmd' not found" ; fi
done

# Swisscom Mobile ID credentials
CERT_FILE=$PWD/mycert.crt                       # The certificate that is allowed to access the service
CERT_KEY=$PWD/mycert.key                        # The related key of the certificate

# Swisscom SDCS elements
SSL_CA=$PWD/allin-ssl.crt                       # Bag file for SSL server connection
OCSP_CERT=$PWD/swisscom-ocsp.crt                # OCSP information of the signers certificate
OCSP_URL=http://ocsp.swissdigicert.ch/sdcs-rubin2

# Create temporary request
RANDOM=$$                                       # Seeds the random number generator from PID of script
INSTANT=$(date +%Y-%m-%dT%H:%M:%S%:z)           # Define instant and request id
REQUESTID=ALLIN.TEST.$((RANDOM%89999+10000)).$((RANDOM%8999+1000))
REQ=$(mktemp /tmp/_tmp.XXXXXX)                  # Request goes here
TIMEOUT_CON=90                                  # Timeout of the client connection

# Hash and digests
DIGEST_VALUE=$1                                 # Hash to be signed
DIGEST_METHOD=$2                                # Digest method
case "$DIGEST_METHOD" in
  "SHA224")
    DIGEST_ALGO='http://www.w3.org/2001/04/xmldsig-more#sha224'
    ;;
  "SHA256")
    DIGEST_ALGO='http://www.w3.org/2001/04/xmlenc#sha256'
    ;;
  "SHA384")
    DIGEST_ALGO='http://www.w3.org/2001/04/xmldsig-more#sha384'
    ;;
  "SHA512")
    DIGEST_ALGO='http://www.w3.org/2001/04/xmlenc#sha512'
    ;;
  *)
    error "Unsupported digest method $DIGEST_METHOD, check with $0"
    ;;
esac

# Target file
PKCS7_RESULT=$3
[ -f "$PKCS7_RESULT" ] && error "Target file $PKCS7_RESULT already exists"

REQ_XML='
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<SignRequest Profile="urn:com:swisscom:dss:v1.0" 
             xmlns:ns2="http://www.w3.org/2000/09/xmldsig#" 
             xmlns="urn:oasis:names:tc:dss:1.0:core:schema">
    <OptionalInputs>
        <ClaimedIdentity>
            <Name>'$AP_ID'</Name>
        </ClaimedIdentity>
        <AdditionalProfile>urn:oasis:names:tc:dss:1.0:profiles:timestamping</AdditionalProfile>
        <SignatureType>urn:ietf:rfc:3161</SignatureType>
    </OptionalInputs>
    <InputDocuments>
        <DocumentHash>
            <ns2:DigestMethod Algorithm="'$DIGEST_ALGO'"/>
            <ns2:DigestValue>'$DIGEST_VALUE'</ns2:DigestValue>
        </DocumentHash>
    </InputDocuments>
</SignRequest>
'

# Trim the request (save some bytes) and store into file
echo "$REQ_XML" | tr -d '\n' > $REQ

# Check existence of needed files
[ -r "${SSL_CA}" ]   || error "CA certificate/chain file ($CERT_CA) missing or not readable"
[ -r "${CERT_KEY}" ]  || error "SSL key file ($CERT_KEY) missing or not readable"
[ -r "${CERT_FILE}" ] || error "SSL certificate file ($CERT_FILE) missing or not readable"
[ -r "${OCSP_CERT}" ] || error "OCSP certificate file ($OCSP_CERT) missing or not readable"

HEADER_CONTENT_TYPE="Content-Type: application/xml"
HEADER_ACCEPT="Accept: application/xml"

# Call the service
URL=https://ais.pre.swissdigicert.ch/DSS-Server/rs/v1.0/sign
CURL_OPTIONS="--sslv3 --silent"
http_code=$(curl --write-out '%{http_code}\n' $CURL_OPTIONS \
    --request POST --data "@${REQ}" --header "${HEADER_ACCEPT}" --header "${HEADER_CONTENT_TYPE}" \
    --cert $CERT_FILE --cacert $SSL_CA --key $CERT_KEY \
    --output $REQ.res --trace-ascii $REQ.log \
    --connect-timeout $TIMEOUT_CON \
    $URL)
    
# Results
export RC=$?
if [ "$RC" = "0" -a "$http_code" -eq 200 ]; then
  # Parse the response xml
  RES_MAJ=$(sed -n -e 's/.*<ResultMajor>\(.*\)<\/ResultMajor>.*/\1/p' $REQ.res)
  RES_MIN=$(sed -n -e 's/.*<ResultMinor>\(.*\)<\/ResultMinor>.*/\1/p' $REQ.res)
  RES_MSG=$(sed -n -e 's/.*<ResultMessage.*>\(.*\)<\/ResultMessage>.*/\1/p' $REQ.res)
  sed -n -e 's/.*<RFC3161TimeStampToken>\(.*\)<\/RFC3161TimeStampToken>.*/\1/p' $REQ.res > $REQ.sig

  if [ -s "${REQ}.sig" ]; then
    # Decode signature if present
    base64 --decode $REQ.sig > $REQ.sig.decoded
    [ -s "${REQ}.sig.decoded" ] || error "Unable to decode Base64Signature"
    # Save PKCS7 content to target
    openssl pkcs7 -inform der -in $REQ.sig.decoded -out $PKCS7_RESULT
    # Extract the signers certificate
    openssl pkcs7 -inform der -in $REQ.sig.decoded -out $REQ.sig.cert -print_certs
    [ -s "${REQ}.sig.cert" ] || error "Unable to extract signers certificate from signature"
    RES_ID_CERT=$(openssl x509 -subject -noout -in $REQ.sig.cert)
  fi

  # Status and results
  if [ "$RES_MAJ" = "urn:oasis:names:tc:dss:1.0:resultmajor:Success" ]; then
    RC=0                                                # Ok
    if [ "$VERBOSE" = "1" ]; then                       # Verbose details
      echo "OK on $DIGEST_VALUE with following details:"
      echo " Signer subject : $RES_ID_CERT"
      echo " Result major   : $RES_MAJ with exit $RC"
    fi
   else
    RC=1                                                # Failure
    if [ "$VERBOSE" = "1" ]; then                       # Verbose details
      echo "FAILED on $DIGEST_VALUE with following details:"
      echo " Result major   : $RES_MAJ with exit $RC"
      echo " Result minor   : $RES_MIN"
      echo " Result message : $RES_MSG"
    fi
  fi
 else
  CURL_ERR=$RC                                          # Keep related error
  export RC=2                                           # Force returned error code
  if [ "$VERBOSE" = "1" ]; then                         # Verbose details
    echo "FAILED on $DIGEST_VALUE with following details:"
    echo " curl error : $CURL_ERR"
    echo " http error : $http_code"
  fi
fi

# Debug details
if [ "$DEBUG" != "" ]; then
  [ -f "$REQ" ] && echo ">>> $REQ <<<" && cat $REQ | xmllint --format -
  [ -f "$REQ.log" ] && echo ">>> $REQ.log <<<" && cat $REQ.log | grep '==\|error'
  [ -f "$REQ.res" ] && echo ">>> $REQ.res <<<" && cat $REQ.res | xmllint --format -
fi

# Cleanups if not DEBUG mode
if [ "$DEBUG" = "" ]; then
  [ -f "$REQ" ] && rm $REQ
  [ -f "$REQ.log" ] && rm $REQ.log
  [ -f "$REQ.res" ] && rm $REQ.res
  [ -f "$REQ.sig" ] && rm $REQ.sig
  [ -f "$REQ.sig.decoded" ] && rm $REQ.sig.decoded
  [ -f "$REQ.sig.cert" ] && rm $REQ.sig.cert
  [ -f "$REQ.sig.cert.check" ] && rm $REQ.sig.cert.check
  [ -f "$REQ.sig.txt" ] && rm $REQ.sig.txt
fi

exit $RC

#==========================================================