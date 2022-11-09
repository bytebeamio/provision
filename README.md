# provision
Tool to generate self signed certificates

### Build Application
'go build provision.go'

### Generate Ca Certificates
`./provision ca`

### Generate Server Certificates
'./provision server --ca {ca cert path} --cakey {ca key path} --domain {domain}'

### Generate Client Certificates
'./provision client --ca {ca cert path} --cakey {ca key path} --device {device id} --tenant {tenant}'
