package machine

import (
	"sheller/util/secret/vault"
	"strings"

	"golang.org/x/crypto/ssh"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

func UnmarshalSecret(d vault.SecretData) (KeyPair, error) {
	var kPair KeyPair
	kPair.PublicKey = d["public"]
	kPair.PrivateKey = d["private"]
	return kPair, nil
}
func AuthMethodFromSecret(kPair KeyPair) (ssh.AuthMethod, error) {
	keyBody := kPair.PrivateKey
	keyBody = strings.Replace(keyBody, `\n`, "\n", -1)
	keyBody = strings.Replace(keyBody, `"`, "", -1)
	priv, err := ssh.ParsePrivateKey([]byte(keyBody))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(priv), nil
}
