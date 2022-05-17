package docker

import (
	"sheller/util/secret/vault"
	"sheller/util/tls"
)

type secretWithTls struct {
	Tls  tls.Tls
	Host string
	Port string
}

func unmarshalSecret(d vault.Secret) (secretWithTls, error) {
	var secret secretWithTls
	secret.Tls.CA = d["ca_cert_file"].(string)
	secret.Tls.Cert = d["cert_file"].(string)
	secret.Tls.Key = d["key_file"].(string)
	secret.Host = d["host"].(string)
	secret.Port = d["port"].(string)
	return secret, nil
}
