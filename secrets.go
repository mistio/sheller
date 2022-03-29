package main

import (
	"encoding/json"
	"log"
	"net/http"
)

var kubernetesSecretsURI = vaultAddr + "/v1/secret/data/sheller/kubernetes/admin"

type KubernetesConfigCredentials struct {
	CertificateAuthorityData string
	ClientCertificateData    string
	ClientKeyData            string
}

/*TODO: use ctx to check for expiry */
func (token *AppRoleClientToken) getSecret() KubernetesConfigCredentials {
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
	return KubernetesConfigCredentials{
		CertificateAuthorityData: result["data"]["data"]["certificate-authority-data"].(string),
		ClientCertificateData:    result["data"]["data"]["client-certificate-data"].(string),
		ClientKeyData:            result["data"]["data"]["client-key-data"].(string),
	}
}
