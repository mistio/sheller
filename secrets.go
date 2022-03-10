package main

import (
	"encoding/json"
	"log"
	"net/http"
)

var kubernetesSecretsURI = vaultAddr + "/v1/secret/data/sheller/kubernetes/admin"

type KubernetesConfigCredentials struct {
	Certificate_authority_data string
	Client_certificate_data    string
	Client_key_data            string
}

func (token *AppRoleClientToken) getSecret() KubernetesConfigCredentials {
	req, err := http.NewRequest("GET", kubernetesSecretsURI, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token.ClientTokenString)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	var result map[string]map[string]map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&result)
	return KubernetesConfigCredentials{
		Certificate_authority_data: result["data"]["data"]["certificate-authority-data"].(string),
		Client_certificate_data:    result["data"]["data"]["client-certificate-data"].(string),
		Client_key_data:            result["data"]["data"]["client-key-data"].(string),
	}
}
