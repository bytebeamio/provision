#! /bin/bash

#! /bin/bash

set -e

# References: 
# https://stackoverflow.com/questions/25482199/verify-a-certificate-chain-using-openssl-verify

# Verify with a ca certificate chain
# openssl verify -verbose -CAfile <(cat Intermediate.pem RootCert.pem) UserCert.pem

# Verify with single ca
# openssl verify -CAfile ca.cert.pem firmware-downloads.bytebeam.io.cert.pem 
#

# Extract certs from device.json
extract() {
  local device_id=$(cat $1|jq -r ".device_id")
  mkdir -p /tmp/certs

  cat $1| jq -r ".authentication.ca_certificate" >/tmp/certs/ca.cert.pem
  cat $1| jq -r ".authentication.device_certificate" >/tmp/certs/$device_id.cert.pem
  cat $1| jq -r ".authentication.device_private_key" >/tmp/certs/$device_id.key.pem
}

show() {
  openssl x509 -in $1 -text
}

verify() {
  #$1 = ca file
  #$2 = cert file
  openssl verify -verbose -CAfile $1 $2
}

# Call functions directly from commandline
"$@"


