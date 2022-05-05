package lxd

import "sheller/util/secret/vault"

func unmarshalSecret(d vault.SecretData) (secretWithTls, error) {
	var secret secretWithTls
	secret.Tls.CA = d["ca_cert_file"]
	secret.Tls.Cert = d["cert_file"]
	secret.Tls.Key = d["key_file"]
	secret.Host = d["host"]
	secret.Port = d["port"]
	return secret, nil
}
