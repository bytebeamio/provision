package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/alexflint/go-arg"
)

// References
// -------------------------------------------------
// https://www.youtube.com/watch?v=VwPQKS9Njv0
// https://docs.google.com/presentation/d/16y-HTvL7ASzf9JspCBX0OVmhwUWVoLj9epzJfNMQRr8/edit#slide=id.p
// https://about.sourcegraph.com/go/gophercon-2019-pki-for-gophers
// https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/

type Config struct {
	Ca     *Ca     `arg:"subcommand:ca" help:"generate ca certs [provision ca]"`
	Server *Server `arg:"subcommand:server" help:"generate server certs [provision server --ca {ca cert} --domain {domain}]"`
	Client *Client `arg:"subcommand:client" help:"generate client certs [provision client --ca {ca cert path} --cakey {ca key path} --device {device id} --tenant {tenant}]"`
	Out    string  `arg:"-o" default:"./"`
}

type Ca struct {
	Bits int `default:"4096" help:"Number of bits"`
}

type Server struct {
	Bits   int    `default:"4096" help:"Number of bits"`
	Ca     string `arg:"required" help:"ca cert path to sign server certificates"`
	CaKey  string `arg:"required" help:"ca key path to sign server certificates"`
	Domain string `arg:"required" help:"domain name"`
}

type Client struct {
	Bits   int    `default:"4096" help:"Number of bits"`
	Ca     string `arg:"required" help:"ca cert path to sign client certificates"`
	CaKey  string `arg:"required" help:"ca key path to sign client certificates"`
	Device string `arg:"required" help:"device name"`
	Tenant string `arg:"required" help:"tenant name"`
}

func (Config) Version() string {
	return "provision 1.0.0"
}

func main() {
	c := Config{}
	parser := arg.MustParse(&c)

	if c.Ca == nil && c.Server == nil && c.Client == nil {
		parser.WriteHelp(os.Stderr)
		os.Exit(255)
	}

	if c.Ca != nil {
		generateCA(c.Ca.Bits, c.Out)
	}

	if c.Server != nil {
		generateServerCerts(c.Server.Bits, c.Server.Ca, c.Server.CaKey, c.Server.Domain, c.Out)
	}

	if c.Client != nil {
		generateClientCerts(c.Client.Bits, c.Client.Ca, c.Client.CaKey, c.Client.Device, c.Client.Tenant, c.Out)
	}
}

func generateCA(bits int, out string) {
	// create our RSA private and public key
	key, err := rsa.GenerateKey(rand.Reader, bits)
	check(err)

	// set up our CA certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"IOT Express Pvt Ltd"},
			Country:       []string{"India"},
			Province:      []string{"Karnataka"},
			Locality:      []string{"Bangalore"},
			StreetAddress: []string{"Subbiah Garden"},
			PostalCode:    []string{"560011"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// create the CA cert and key data in DER. Sign the CA with the same CA
	caPrivateKeyDER := x509.MarshalPKCS1PrivateKey(key)
	caCertDER, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	check(err)

	// pem encode
	caCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: caCertDER, Type: "CERTIFICATE"})
	caPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Bytes: caPrivateKeyDER, Type: "RSA PRIVATE KEY"})

	out = out + "/"
	caKeyFile, err := os.Create(out + "ca.key.pem")
	check(err)
	caKeyFile.Write(caPrivateKeyPEM)

	caCertFile, err := os.Create(out + "ca.cert.pem")
	check(err)
	caCertFile.Write(caCertPEM)
	fmt.Printf("%q\n", caCertPEM)
}

func generateServerCerts(bits int, caCertPath, caKeyPath, domain string, out string) {
	caPrivateKeyPEM, err := ioutil.ReadFile(caKeyPath)
	check(err)

	caKey, _ := pem.Decode([]byte(caPrivateKeyPEM))
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caKey.Bytes)
	check(err)

	caCertPEM, err := ioutil.ReadFile(caCertPath)
	check(err)

	caCertBytes, _ := pem.Decode([]byte(caCertPEM))
	caCert, err := x509.ParseCertificate(caCertBytes.Bytes)
	check(err)

	// create our RSA private and public key
	key, err := rsa.GenerateKey(rand.Reader, bits)
	check(err)

	// set up our CA certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:    domain,
			Organization:  []string{"Bytebeam.io"},
			Country:       []string{"India"},
			Province:      []string{"Karnataka"},
			Locality:      []string{"Bangalore"},
			StreetAddress: []string{"Subbiah Garden"},
			PostalCode:    []string{"560011"},
		},
		DNSNames:    []string{domain},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	// create the CA cert and key data in DER. Sign the CA with the same CA
	serverPrivateKeyDER := x509.MarshalPKCS1PrivateKey(key)
	serverCertDER, err := x509.CreateCertificate(rand.Reader, cert, caCert, key.Public(), caPrivateKey)
	check(err)

	// pem encode
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: serverCertDER, Type: "CERTIFICATE"})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Bytes: serverPrivateKeyDER, Type: "RSA PRIVATE KEY"})

	out = out + "/"
	serverKeyFile, err := os.Create(out + domain + ".key.pem")
	check(err)
	serverKeyFile.Write(serverKeyPEM)

	serverCertFile, err := os.Create(out + domain + ".cert.pem")
	check(err)
	serverCertFile.Write(serverCertPEM)
	fmt.Printf("%v\n", string(serverCertPEM))
}

func generateClientCerts(bits int, caCertPath, caKeyPath, deviceName, tenantName string, out string) {
	caPrivateKeyPEM, err := ioutil.ReadFile(caKeyPath)
	check(err)

	caKey, _ := pem.Decode([]byte(caPrivateKeyPEM))
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caKey.Bytes)
	check(err)

	caCertPEM, err := ioutil.ReadFile(caCertPath)
	check(err)

	caCertBytes, _ := pem.Decode([]byte(caCertPEM))
	caCert, err := x509.ParseCertificate(caCertBytes.Bytes)
	check(err)

	// create our RSA private and public key
	key, err := rsa.GenerateKey(rand.Reader, bits)
	check(err)

	// set up our CA certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   deviceName,
			Organization: []string{tenantName},
		},
		DNSNames:    []string{deviceName},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	// create the CA cert and key data in DER. Sign the CA with the same CA
	serverPrivateKeyDER := x509.MarshalPKCS1PrivateKey(key)
	serverCertDER, err := x509.CreateCertificate(rand.Reader, cert, caCert, key.Public(), caPrivateKey)
	check(err)

	// pem encode
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: serverCertDER, Type: "CERTIFICATE"})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Bytes: serverPrivateKeyDER, Type: "RSA PRIVATE KEY"})

	out = out + "/"
	clientKeyFile, err := os.Create(out + deviceName + ".key.pem")
	check(err)
	clientKeyFile.Write(clientKeyPEM)
	fmt.Printf("%q\n", clientKeyPEM)

	clientCertFile, err := os.Create(out + deviceName + ".cert.pem")
	check(err)

	println(clientCertFile.Name())
	clientCertFile.Write(clientCertPEM)
	fmt.Printf("%q\n", clientCertPEM)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
