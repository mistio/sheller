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

func unmarshalSecret(d vault.SecretData) (secretWithTls, error) {
	var secret secretWithTls
	secret.Tls.CA = d["ca_cert_file"]
	secret.Tls.Cert = d["cert_file"]
	secret.Tls.Key = d["key_file"]
	secret.Host = d["host"]
	secret.Port = d["port"]
	return secret, nil
}
