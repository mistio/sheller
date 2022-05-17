package kubernetes

import (
	b64 "encoding/base64"
	"errors"
	"sheller/util/secret/vault"
)

type Info struct {
	User        string
	Password    string `datapolicy:"password"`
	CAFile      string
	CertFile    string
	KeyFile     string
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
	host = Host(d["host"].(string) + ":" + d["port"].(string))
	info := Info{}
	_, hasTLS := d["ca_cert_file"]
	if hasTLS {
		info.CAFile = b64.StdEncoding.EncodeToString([]byte("ca_cert_file"))
		info.CertFile = b64.StdEncoding.EncodeToString([]byte(d["cert_file"].(string)))
		info.KeyFile = b64.StdEncoding.EncodeToString([]byte(d["key_file"].(string)))
	}
	_, hasUser := d["username"]
	if hasUser {
		info.User = d["username"].(string)
		_, hasPassword := d["password"]
		if hasPassword {
			info.Password = d["password"].(string)
		}
	}
	_, hasBearerToken := d["bearer_token"]
	if hasBearerToken {
		info.BearerToken = d["bearer_token"].(string)
	}
	return info, host, info.Complete()
}

// Complete returns true if the Kubernetes API authorization info is complete.
func (info Info) Complete() error {
	if len(info.User) > 0 ||
		(len(info.CertFile) > 0 && len(info.CAFile) > 0 && len(info.KeyFile) > 0) ||
		len(info.BearerToken) > 0 {
		return nil
	} else {
		return errors.New("could not find any kubernetes credentials")
	}

}
