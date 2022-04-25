package secret

import (
	b64 "encoding/base64"
	"sheller/types/docker"
	"sheller/types/kubernetes"
	MachineSSH "sheller/types/ssh"
	"sheller/types/vault"
)

func unmarshalMachineSSHKeyPair(r vault.SecretPayload) (MachineSSH.KeyPair, error) {
	var keyPair MachineSSH.KeyPair
	keyPair.PublicKey = r["data"]["data"]["public"]
	keyPair.PrivateKey = r["data"]["data"]["private"]

	return keyPair, nil
}

func unmarshalKubernetesSecretWithTls(r vault.SecretPayload) (kubernetes.SecretWithTls, error) {
	var secret kubernetes.SecretWithTls
	// todo:check if format of tls data is existent and correct
	// and return any possible errors
	secret.Tls.CA = b64.StdEncoding.EncodeToString([]byte(r["data"]["data"]["ca_cert_file"]))
	secret.Tls.Cert = b64.StdEncoding.EncodeToString([]byte(r["data"]["data"]["cert_file"]))
	secret.Tls.Key = b64.StdEncoding.EncodeToString([]byte(r["data"]["data"]["key_file"]))
	secret.Host = r["data"]["data"]["host"]
	secret.Port = r["data"]["data"]["port"]

	return secret, nil
}

func unmarshalDockerSecretWithTls(r vault.SecretPayload) (docker.SecretWithTls, error) {
	var secret docker.SecretWithTls
	secret.Tls.CA = r["data"]["data"]["ca_cert_file"]
	secret.Tls.Cert = r["data"]["data"]["cert_file"]
	secret.Tls.Key = r["data"]["data"]["key_file"]
	secret.Host = r["data"]["data"]["host"]
	secret.Port = r["data"]["data"]["port"]
	return secret, nil
}
