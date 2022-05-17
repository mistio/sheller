// vault getss wgatete
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
	req, err := http.NewRequest("GET", string(p), nil)
	if err != nil {
		return nil, err
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
	data := r["data"].(map[string]any)
	return Secret(data["data"].(map[string]any)), nil
}
