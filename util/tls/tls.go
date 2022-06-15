package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func createTLSCert(cert, key []byte) (tls.Certificate, error) {
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating cert: %v", err)
	}
	return tlsCert, err
}

func createCertPool(ca []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(ca)
	if !ok {
		return &x509.CertPool{}, fmt.Errorf("error creating cert pool")
	}
	return certPool, nil
}

func CreateTLSConfig(cert, key, ca []byte) (*tls.Config, error) {
	tlsCert, err := createTLSCert(cert, key)
	if err != nil {
		return nil, err
	}
	certPool, err := createCertPool(ca)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      certPool,
	}
	return cfg, nil
}
