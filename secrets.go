package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

var (
	baseAddress string
	loginAddr   = baseAddress + "v1/auth/approle/login"
)

type secretsURIData struct {
	Name  string
	Cloud string
}
type AppRoleLoginPayload struct {
	Role_id   string `json:"role_id"`
	Secret_id string `json:"secret_id"`
}

type AppRoleClientToken struct {
	Token         string
	TokenDuration time.Duration
}

type KubernetesConfigCredentials struct {
	ca_cert_file string
	cert_file    string
	key_file     string
	host         string
	port         string
}

func (AppRoleLoginPayload *AppRoleLoginPayload) Login() AppRoleClientToken {
	payload, err := json.Marshal(AppRoleLoginPayload)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := http.Post(loginAddr, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Fatal(err)
	}
	var result map[string]map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&result)
	return AppRoleClientToken{Token: result["auth"]["client_token"].(string), TokenDuration: time.Duration(result["auth"]["token_duration"].(time.Duration))}
}

func (token *AppRoleClientToken) getSecret(u secretsURIData) KubernetesConfigCredentials {
	kubernetesSecretsURI := fmt.Sprintf("%s/v1/%s/data/mist/clouds/%s", baseAddress, u.Name, u.Cloud)
	req, err := http.NewRequest("GET", kubernetesSecretsURI, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	var result map[string]map[string]map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&result)
	/*weird way to do this*/
	return KubernetesConfigCredentials{
		ca_cert_file: result["data"]["data"]["ca_cert_file"].(string),
		cert_file:    result["data"]["data"]["cert_file"].(string),
		key_file:     result["data"]["data"]["key_file"].(string),
		host:         result["data"]["data"]["host"].(string),
		port:         result["data"]["data"]["port"].(string),
	}
}
