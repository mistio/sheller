package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	cryptoSheller "sheller/crypto"
	"sheller/secret"
	"sheller/types/vault"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

func MachineSSHCfg(vars map[string]string) (*ssh.ClientConfig, error) {
	user := vars["user"]
	host := vars["host"]
	port := vars["port"]
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)

	mac := vars["mac"]
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))
	h.Write([]byte(user + "," + host + "," + port + "," + vars["expiry"] + "," + vars["encrypted_msg"]))
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		return nil, fmt.Errorf("Invalid MAC")
	}
	decryptedMessage := cryptoSheller.Decrypt(vars["encrypted_msg"], "")
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := plaintextParts[0]
	secretPath := plaintextParts[1]
	keyName := plaintextParts[2]
	vault := vault.AccessWithToken{
		Vault: vault.Vault{
			Address:    os.Getenv("VAULT_ADDR"),
			SecretPath: fmt.Sprintf("/v1/%s/data/mist/keys/%s", secretPath, keyName),
		},
		Token: token,
	}
	priv, err := secret.KeyPairRequest(vault, expiry)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			priv,
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}, nil
}
