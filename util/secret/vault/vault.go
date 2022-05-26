package vault

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type Token string
type SecretPath string
type Secret map[string]any

func GetSecret(t Token, p SecretPath, expiry int64) (Secret, error) {
	if expiry < time.Now().Unix() {
		return nil, errors.New("session expired")
	}
	if t == "" {
		return nil, errors.New("token is empty")
	}
	req, err := http.NewRequest("GET", string(p), nil)
	if err != nil {
		return nil, err
	}
	if p == "" {
		return nil, errors.New("secret path is empty")
	}
	req.Header.Set("X-Vault-Token", string(t))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var r map[string]any
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&r)
	if err != nil {
		return nil, err
	}
	data, ok := r["data"].(map[string]any)
	if !ok {
		return Secret{}, errors.New("vault response for secret not in expected format")
	}
	secret, ok := data["data"].(map[string]any)
	if !ok {
		return Secret{}, errors.New("vault response for secret not in expected format")
	}
	return Secret(secret), nil
}
