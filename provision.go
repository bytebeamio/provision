package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

// References
// -------------------------------------------------
// https://www.youtube.com/watch?v=VwPQKS9Njv0
// https://docs.google.com/presentation/d/16y-HTvL7ASzf9JspCBX0OVmhwUWVoLj9epzJfNMQRr8/edit#slide=id.p
// https://about.sourcegraph.com/go/gophercon-2019-pki-for-gophers
// https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/

var genCA *bool = flag.Bool("ca", false, "Generate fresh CA key and cert to sign server and client certificates. \nUsage: ./provision -ca")
var genServer *string = flag.String("server", "", "Generate server certificate key pair. \nUsage: ./provision -server mqtt.bytebeam.io")
var genClient *string = flag.String("client", "", "Generate client certificate key pair. \nUsage: ./provision -client device-1")

func init() {
	flag.Parse()
}

func main() {
	if *genCA {
		generateCA()
	}

	if *genServer != "" {
		generateServerCerts(*genServer)
	}

	if *genClient != "" {
		generateClientCerts(*genClient)
	}
}

func generateCA() {
	// create our RSA private and public key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	check(err)

	// set up our CA certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
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

	caKey, err := os.Create("./ca.key.pem")
	check(err)
	caKey.Write(caPrivateKeyPEM)
	caCert, err := os.Create("./ca.cert.pem")
	check(err)
	caCert.Write(caCertPEM)
}

func generateServerCerts(domain string) {
	caPrivateKeyPEM, err := ioutil.ReadFile("./ca.key.pem")
	check(err)

	caKey, _ := pem.Decode([]byte(caPrivateKeyPEM))
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caKey.Bytes)
	check(err)

	caCertPEM, err := ioutil.ReadFile("./ca.cert.pem")
	check(err)

	caCertBytes, _ := pem.Decode([]byte(caCertPEM))
	caCert, err := x509.ParseCertificate(caCertBytes.Bytes)
	check(err)

	// create our RSA private and public key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	check(err)

	// set up our CA certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:    domain,
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
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
	serverPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Bytes: serverPrivateKeyDER, Type: "RSA PRIVATE KEY"})

	serverKey, err := os.Create(domain + ".key.pem")
	check(err)
	serverKey.Write(serverPrivateKeyPEM)
	serverCert, err := os.Create(domain + ".cert.pem")
	check(err)
	serverCert.Write(serverCertPEM)
}

func generateClientCerts(deviceName string) {
	caPrivateKeyPEM, err := ioutil.ReadFile("./ca.key.pem")
	check(err)

	caKey, _ := pem.Decode([]byte(caPrivateKeyPEM))
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caKey.Bytes)
	check(err)

	caCertPEM, err := ioutil.ReadFile("./ca.cert.pem")
	check(err)

	caCertBytes, _ := pem.Decode([]byte(caCertPEM))
	caCert, err := x509.ParseCertificate(caCertBytes.Bytes)
	check(err)

	// create our RSA private and public key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	check(err)

	// set up our CA certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   deviceName,
			Organization: []string{"Company, INC."},
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
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: serverCertDER, Type: "CERTIFICATE"})
	serverPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{Bytes: serverPrivateKeyDER, Type: "RSA PRIVATE KEY"})

	serverKey, err := os.Create(deviceName + ".key.pem")
	check(err)
	serverKey.Write(serverPrivateKeyPEM)
	serverCert, err := os.Create(deviceName + ".cert.pem")
	check(err)
	serverCert.Write(serverCertPEM)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
