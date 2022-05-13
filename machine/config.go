package machine

import (
	"fmt"
	"os"
	"sheller/util/conceal"
	"sheller/util/secret/vault"
	"strings"

	"golang.org/x/crypto/ssh"
)

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

func Cfg(EncryptedMessage string, expiry int64) (ssh.AuthMethod, error) {
	decryptedMessage := conceal.Decrypt(EncryptedMessage, "")
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := plaintextParts[0]
	secretPath := plaintextParts[1]
	keyName := plaintextParts[2]
	vaultConfig := vault.AccessWithToken{
		Vault: vault.Vault{
			Address:    os.Getenv("VAULT_ADDR"),
			SecretPath: fmt.Sprintf("/v1/%s/data/mist/keys/%s", secretPath, keyName),
		},
		Token: token,
	}
	secretData, err := vault.SecretRequest(vaultConfig, expiry)
	if err != nil {
		return nil, err
	}
	kPair, err := UnmarshalSecret(secretData)
	if err != nil {
		return nil, err
	}
	priv, err := AuthMethodFromSecret(kPair)
	return priv, err
}
