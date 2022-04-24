package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Vault struct {
	address    string
	secretPath string
	token      string
}

type MachineKeys struct {
	PublicKey  string `json:"public"`
	PrivateKey string `json:"private"`
}

type KubernetesConfigCredentials struct {
	Ca_cert_file string
	Cert_file    string
	Key_file     string
	Host         string
	Port         string
	//user
	//context
}
type DockerConfigCredentials struct {
	Ca_cert_file string
	Cert_file    string
	Key_file     string
	Host         string
	Port         string
}

type result map[string]map[string]map[string]string

func unmarshalMachineKeys(r result) (MachineKeys, error) {
	var keys MachineKeys
	Result := func(value string) string {
		return r["data"]["data"][value]
	}
	keys.PublicKey = Result("public")
	keys.PrivateKey = Result("private")
	return keys, nil
}
func unmarshalKubernetesConfigCredentials(r result) (KubernetesConfigCredentials, error) {
	var c KubernetesConfigCredentials
	Result := func(value string) string {
		return r["data"]["data"][value]
	}
	c.Ca_cert_file = b64.StdEncoding.EncodeToString([]byte(Result("ca_cert_file")))
	c.Cert_file = b64.StdEncoding.EncodeToString([]byte(Result("cert_file")))
	c.Key_file = b64.StdEncoding.EncodeToString([]byte(Result("key_file")))
	c.Host = Result("host")
	c.Port = Result("port")
	return c, nil
}
func unmarshalDockerConfigCredentials(r result) (DockerConfigCredentials, error) {
	var c DockerConfigCredentials
	Result := func(value string) string {
		// add a new line to the end of the string
		return r["data"]["data"][value] + "\n"
	}

	c.Ca_cert_file = Result("ca_cert_file")
	c.Cert_file = Result("cert_file")
	c.Key_file = Result("key_file")
	c.Host = Result("host")
	c.Port = Result("port")
	return c, nil
}
func GetPrivateKey(v Vault, expiry int64) (ssh.AuthMethod, error) {

	if expiry < time.Now().Unix() {
		return nil, errors.New("Session expired")
	}

	uri := v.address + v.secretPath
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	var r result
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	keys, err := unmarshalMachineKeys(r)
	keyBody := keys.PrivateKey
	keyBody = strings.Replace(keyBody, `\n`, "\n", -1)
	keyBody = strings.Replace(keyBody, `"`, "", -1)
	priv, err := ssh.ParsePrivateKey([]byte(keyBody))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(priv), nil
}
func GetKubernetesConfigCredentials(v Vault) (KubernetesConfigCredentials, error) {
	uri := v.address + v.secretPath
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
		return KubernetesConfigCredentials{}, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
		return KubernetesConfigCredentials{}, err
	}
	var r result
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	credentials, err := unmarshalKubernetesConfigCredentials(r)
	return credentials, nil
}

func GetDockerConfigCredentials(v Vault) (DockerConfigCredentials, error) {
	uri := v.address + v.secretPath
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
		return DockerConfigCredentials{}, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
		return DockerConfigCredentials{}, err
	}
	var r result
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&r)
	credentials, err := unmarshalDockerConfigCredentials(r)
	return credentials, nil
}
