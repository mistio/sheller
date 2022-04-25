package secret

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sheller/types/docker"
	"sheller/types/kubernetes"
	"sheller/types/vault"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func KeyPairRequest(v vault.AccessWithToken, expiry int64) (ssh.AuthMethod, error) {
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

func KubernetesSecretWithTlsRequest(v vault.AccessWithToken, expiry int64) (kubernetes.SecretWithTls, error) {
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
	var r vault.SecretPayload
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	credentials, err := unmarshalKubernetesSecretWithTls(r)
	return credentials, nil
}

func DockerSecretWithTlsRequest(v vault.AccessWithToken, expiry int64) (docker.SecretWithTls, error) {
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
