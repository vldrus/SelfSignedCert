package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type stringArray []string

func (i *stringArray) String() string {
	return strings.Join(*i, ", ")
}

func (i *stringArray) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var ctype string
	flag.StringVar(&ctype, "type", "ec", "Certificate type, \"ec\" or \"rsa\"")

	var name string
	flag.StringVar(&name, "name", "App", "Common name for certificate")

	var dnss stringArray
	flag.Var(&dnss, "dns", "DNS name for certificate")

	var ips stringArray
	flag.Var(&ips, "ip", "IP address for certificate")

	flag.Parse()

	fmt.Println("Generating self-signed certificate:")
	fmt.Println(" - Type:        ", ctype)
	fmt.Println(" - Common name: ", name)
	fmt.Println(" - DNS names:   ", dnss)
	fmt.Println(" - IP addresses:", ips)

	now := time.Now()

	var pkey crypto.Signer
	var err error

	switch ctype {
	case "ec":
		pkey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		pkey, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		err = fmt.Errorf("unknown type")
	}
	if err != nil {
		exitWithError("Cannot generate certificate key", err)
	}

	var cips []net.IP
	for _, ip := range ips {
		cip := net.ParseIP(ip)
		if cip == nil {
			fmt.Println("Note:", ip, "is not valid IP address")
			continue
		}
		cips = append(cips, cip)
	}

	cert := x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Issuer:       pkix.Name{CommonName: name},
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now,
		NotAfter:     now.AddDate(100, 0, 0),
		DNSNames:     dnss,
		IPAddresses:  cips,
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	buf, err := x509.CreateCertificate(rand.Reader, &cert, &cert, pkey.Public(), pkey)
	if err != nil {
		exitWithError("Cannot generate certificate", err)
	}
	crt, err := os.Create("cert.crt")
	if err != nil {
		exitWithError("Cannot create file 'cert.crt'", err)
	}
	err = pem.Encode(crt, &pem.Block{Type: "CERTIFICATE", Bytes: buf})
	if err != nil {
		exitWithError("Cannot save certificate", err)
	}

	buf, err = x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		exitWithError("Cannot generate private key", err)
	}
	key, err := os.Create("cert.key")
	if err != nil {
		exitWithError("Cannot create file 'cert.key'", err)
	}
	err = pem.Encode(key, &pem.Block{Type: "PRIVATE KEY", Bytes: buf})
	if err != nil {
		exitWithError("Cannot save private key", err)
	}

	fmt.Println("Done. Certificate saved to 'cert.crt' and 'cert.key'.")
}

func exitWithError(msg string, err error) {
	fmt.Fprintln(os.Stderr, msg, "-", err)
	fmt.Fprintln(os.Stderr, "Exiting now.")
	os.Exit(1)
}
