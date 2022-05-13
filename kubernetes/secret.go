package kubernetes

import (
	b64 "encoding/base64"
	"sheller/util/secret/vault"
	"sheller/util/tls"
)

type secretWithTls struct {
	Tls  tls.Tls
	Host string
	Port string
	// user string
	// context string
}

func unmarshalSecret(d vault.SecretData) (secretWithTls, error) {
	var secret secretWithTls
	// todo:check if format of tls data is existent and correct
	// and return any possible errors
	secret.Tls.CA = b64.StdEncoding.EncodeToString([]byte(d["ca_cert_file"]))
	secret.Tls.Cert = b64.StdEncoding.EncodeToString([]byte(d["cert_file"]))
	secret.Tls.Key = b64.StdEncoding.EncodeToString([]byte(d["key_file"]))
	secret.Host = d["host"]
	secret.Port = d["port"]
	return secret, nil
}

/*
TO-DO: support other ways to authenticate with kubernetes clusters
ex. username,password
type UserPass struct {
	User string
	Password string
}
type VaultUserPassSecret struct {
	UserPass UserPass
	Host string
	Port string
}
*/
