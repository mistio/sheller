package vault

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

type SecretResponse map[string]map[string]map[string]string

type SecretData map[string]string

func SecretRequest(v AccessWithToken, expiry int64) (SecretData, error) {
	if expiry < time.Now().Unix() {
		return nil, errors.New("Session expired")
	}
	uri := v.Vault.Address + v.Vault.SecretPath
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
	}
	// in the future the header should be an input parameter
	// so we can avoid writing different
	req.Header.Set("X-Vault-Token", v.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	var r SecretResponse
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	return SecretData(r["data"]["data"]), nil
}

/*
func KeyPairRequest(v AccessWithToken, expiry int64) (ssh.AuthMethod, error) {
	if expiry < time.Now().Unix() {
		return nil, errors.New("Session expired")
	}

	uri := v.Vault.Address + v.Vault.SecretPath
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
	}
	// in the future the header should be an input parameter
	// so we can avoid writing different
	req.Header.Set("X-Vault-Token", v.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	var r vault.SecretPayload
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	keys, err := unmarshalMachineSSHKeyPair(r)
	keyBody := keys.PrivateKey
	keyBody = strings.Replace(keyBody, `\n`, "\n", -1)
	keyBody = strings.Replace(keyBody, `"`, "", -1)
	priv, err := ssh.ParsePrivateKey([]byte(keyBody))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(priv), nil
}

func KubernetesSecretWithTlsRequest(v AccessWithToken, expiry int64) (kubernetes.SecretWithTls, error) {
	if expiry < time.Now().Unix() {
		return kubernetes.SecretWithTls{}, errors.New("Session expired")
	}
	uri := v.Vault.Address + v.Vault.SecretPath
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
		return kubernetes.SecretWithTls{}, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
		return kubernetes.SecretWithTls{}, err
	}
	var r SecretPayload
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	credentials, err := unmarshalKubernetesSecretWithTls(r)
	return credentials, nil
}

func DockerSecretWithTlsRequest(v AccessWithToken, expiry int64) (docker.SecretWithTls, error) {
	if expiry < time.Now().Unix() {
		return docker.SecretWithTls{}, errors.New("Session expired")
	}
	uri := v.Vault.Address + v.Vault.SecretPath
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
		return docker.SecretWithTls{}, err
	}
	req.Header.Set("X-Vault-Token", v.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
		return docker.SecretWithTls{}, err
	}
	var r vault.SecretPayload
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	credentials, err := unmarshalDockerSecretWithTls(r)
	return credentials, nil
}
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

*/
