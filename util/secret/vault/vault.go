package vault

import (
	"encoding/json"
	"net/http"
	"time"
)

type (
	Token      string
	SecretPath string
	Secret     map[string]any
)

func GetSecret(t Token, p SecretPath, expiry int64) (Secret, error) {
	if expiry < time.Now().Unix() {
		return nil, ErrSessionExpired
	}
	if p == "" {
		return nil, ErrEmptySecretPath
	}
	req, err := http.NewRequest("GET", string(p), nil)
	if err != nil {
		return nil, err
	}
	if t == "" {
		return nil, ErrEmptyToken
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
		return Secret{}, ErrInvalidResponseFormat
	}
	secret, ok := data["data"].(map[string]any)
	if !ok {
		return Secret{}, ErrInvalidResponseFormat
	}
	return Secret(secret), nil
}
