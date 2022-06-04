package machine

import (
	"errors"
	"os"
	"sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

func GetPrivateKey(vars map[string]string) (ssh.AuthMethod, error) {
	secret := []byte(os.Getenv("INTERNAL_KEYS_SECRET"))
	if len(secret) == 0 {
		secretFromFile, err := os.ReadFile("secrets/secret.txt")
		if err != nil {
			return nil, err
		}
		secret = secretFromFile
	}
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], secret, []byte{})
	if err != nil {
		return nil, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	vault_addr := vault.SecretPath(plaintextParts[1])
	vault_secret_engine_path := vault.SecretPath(plaintextParts[2])
	key_path := vault.SecretPath(plaintextParts[3])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return nil, err
	}
	secretPath := vault_addr + "/v1/" + vault_secret_engine_path + "/data/" + key_path
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return nil, err
	}
	var kPair KeyPair
	var ok bool
	kPair.PublicKey, ok = secretData["public"].(string)
	if !ok {
		return nil, errors.New("can't read public key")
	}
	kPair.PrivateKey, ok = secretData["private"].(string)
	if !ok {
		return nil, errors.New("can't read private key")
	}
	keyBody := kPair.PrivateKey
	keyBody = strings.Replace(keyBody, `\n`, "\n", -1)
	keyBody = strings.Replace(keyBody, `"`, "", -1)
	priv, err := ssh.ParsePrivateKey([]byte(keyBody))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(priv), nil
}
