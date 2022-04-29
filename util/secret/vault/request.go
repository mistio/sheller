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
