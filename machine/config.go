package machine

import (
	"sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

func Cfg(vars map[string]string) (ssh.AuthMethod, error) {
	decryptedMessage := conceal.Decrypt(vars["encrypted_msg"], "")
	vaultConfig := vault.CreateVaultAccessWithToken(decryptedMessage)
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
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
