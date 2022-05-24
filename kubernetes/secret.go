package kubernetes

import (
	"errors"
	"sheller/util/secret/vault"
)

type Info struct {
	CAData      []byte
	CertData    []byte
	KeyData     []byte
	BearerToken string `datapolicy:"token"`
	Insecure    *bool
}

type Host string

func unmarshalSecret(d vault.Secret) (Info, Host, error) {
	var host Host
	_, hasHost := d["host"]
	if !hasHost {
		return Info{}, "", errors.New("did not provide host")
	}
	_, hasPort := d["port"]
	if !hasPort {
		return Info{}, "", errors.New("did not provide port")
	}
	host = Host("https://" + d["host"].(string) + ":" + d["port"].(string))
	info := Info{}
	_, hasCA := d["ca_cert_file"]
	if hasCA {
		info.CAData = []byte(d["ca_cert_file"].(string))
	}
	_, hascert := d["cert_file"]
	if hascert {
		info.CertData = []byte(d["cert_file"].(string))
	}
	_, haskey := d["key_file"]
	if haskey {
		info.KeyData = []byte(d["key_file"].(string))
	}
	_, hasBearerToken := d["token"]
	if hasBearerToken {
		info.BearerToken = d["token"].(string)

	}
	return info, host, nil
}

// Complete returns true if the Kubernetes API authorization info is complete.
func (info Info) Complete() error {
	if (len(info.CAData) > 0 && len(info.BearerToken) > 0) ||
		(len(info.CAData) > 0 && len(info.CertData) > 0 && len(info.KeyData) > 0) {
		return nil
	} else {
		return errors.New("could not find the necessary kubernetes credentials")
	}

}
