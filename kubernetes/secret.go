package kubernetes

import (
	"errors"
	"sheller/util/secret/vault"

	"k8s.io/client-go/rest"
)

type Secret struct {
	CAData      []byte
	CertData    []byte
	KeyData     []byte
	BearerToken string `datapolicy:"token"`
	Insecure    *bool
}

type Host string

func unmarshalSecret(d vault.Secret) (Secret, string, error) {
	s := Secret{}
	_, hasCA := d["ca_cert_file"]
	if hasCA {
		CAData, ok := d["ca_cert_file"].(string)
		if !ok {
			return Secret{}, "", errors.New("can't read ca certificate")
		}
		s.CAData = []byte(CAData)
	}
	_, hascert := d["cert_file"]
	if hascert {
		CertData, ok := d["cert_file"].(string)
		if !ok {
			return Secret{}, "", errors.New("can't read client certificate")
		}
		s.CertData = []byte(CertData)
	}
	_, haskey := d["key_file"]
	if haskey {
		KeyData, ok := d["key_file"].(string)
		if !ok {
			return Secret{}, "", errors.New("can't read key")
		}
		s.KeyData = []byte(KeyData)
	}
	_, hasBearerToken := d["token"]
	if hasBearerToken {
		BearerToken, ok := d["token"].(string)
		if !ok {
			return Secret{}, "", errors.New("can't read bearer token")
		}
		s.BearerToken = BearerToken
	}
	_, hasHost := d["host"]
	if !hasHost {
		return Secret{}, "", errors.New("did not provide host")
	}
	Host, ok := d["host"].(string)
	if !ok {
		return Secret{}, "", errors.New("can't read host")
	}
	_, hasPort := d["port"]
	if !hasPort {
		return Secret{}, "", errors.New("did not provide port")
	}
	Port, ok := d["port"].(string)
	if !ok {
		return Secret{}, "", errors.New("can't read port")
	}
	host := "https://" + Host + ":" + Port
	return s, host, nil
}

func (s Secret) Complete() error {
	if (len(s.CAData) > 0 && len(s.BearerToken) > 0) ||
		(len(s.CAData) > 0 && len(s.CertData) > 0 && len(s.KeyData) > 0) {
		return nil
	} else {
		return errors.New("could not find the necessary kubernetes credentials")
	}

}

func (s Secret) MergeWithConfig(c rest.Config) rest.Config {
	var config = c
	config.CAData = s.CAData
	if s.BearerToken == "" {
		config.CertData = s.CertData
		config.KeyData = s.KeyData
	} else {
		config.BearerToken = s.BearerToken
	}
	if s.Insecure != nil {
		config.Insecure = *s.Insecure
	}
	return config
}
