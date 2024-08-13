package gocert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func CreateCertificate(conf CertConfig) ([]byte, []byte, error) {
	ca := createCertificate(conf)

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024*4)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate private key: %w", err)
	}
	caPrivateKey := privateKey

	template, parent := ca, ca
	if conf.Metadata.CaCertPath != "" && conf.Metadata.CaKeyPath != "" {
		cert, err := os.ReadFile(conf.Metadata.CaCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot read cert: %w", err)
		}

		key, err := os.ReadFile(conf.Metadata.CaKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot read key: %w", err)
		}

		parent, caPrivateKey, err = pem2cert(cert, key)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot convert cert / key files to objects: %w", err)
		}
	} else if !conf.Metadata.IsCa {
		return nil, nil, fmt.Errorf("leaf cert need CA cert and key specified in config")
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM, keyPEM := cert2pem(caBytes, privateKey)
	return certPEM, keyPEM, nil
}

func createCertificate(conf CertConfig) *x509.Certificate {
	ips := make([]net.IP, len(conf.DNS.IPs))
	for i, v := range conf.DNS.IPs {
		ips[i] = net.ParseIP(v)
	}

	return &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  conf.Subject.Organization,
			CommonName:    conf.Subject.CommonName,
			Country:       conf.Subject.Country,
			Province:      conf.Subject.Province,
			Locality:      conf.Subject.Locality,
			StreetAddress: conf.Subject.StreetAddress,
			PostalCode:    conf.Subject.PostalCode,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(conf.Metadata.Expiration.Years, conf.Metadata.Expiration.Months, conf.Metadata.Expiration.Days),
		IsCA:                  conf.Metadata.IsCa,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              conf.DNS.Domains,
	}

}

func cert2pem(cert []byte, privateKey *rsa.PrivateKey) ([]byte, []byte) {
	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		panic("cannot encode cert to pem format:" + err.Error())
	}

	privateKeyPEM := new(bytes.Buffer)
	err = pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		panic("cannot encode cert to pem format:" + err.Error())
	}

	return certPEM.Bytes(), privateKeyPEM.Bytes()
}

func pem2cert(cert, key []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	block, _ := pem.Decode(cert)
	certObj, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse bytes as cert: %w", err)
	}

	block, _ = pem.Decode(key)
	keyObj, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse bytes as key: %w", err)
	}

	return certObj, keyObj, nil
}
