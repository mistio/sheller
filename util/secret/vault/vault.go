package vault

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type Token string
type SecretPath string
type SecretResponse map[string]any
type Secret map[string]any
type SecretRequest struct {
	Token Token
	Path  SecretPath
}

func GetSecretRequest(decryptedMessage string) SecretRequest {
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := Token(plaintextParts[0])
	path := SecretPath(plaintextParts[1])
	return SecretRequest{token, path}
}

func (secretRequest SecretRequest) GetSecret(expiry int64) (Secret, error) {
	if expiry < time.Now().Unix() {
		return nil, errors.New("Session expired")
	}
	req, err := http.NewRequest("GET", string(secretRequest.Path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", string(secretRequest.Token))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var r SecretResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&r)
	if err != nil {
		return nil, err
	}
	data := r["data"].(map[string]any)
	return Secret(data["data"].(map[string]any)), nil
}
