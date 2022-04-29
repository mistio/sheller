package machine

import (
	"fmt"
	"log"
	"net"
	"os"
	"sheller/util/conceal"
	"sheller/util/secret/vault"
	"sheller/util/verify"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type execConfig struct {
	User string
	Host string
	Port string
}

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

func SHHCfg(vars map[string]string) (*ssh.ClientConfig, error) {
	user := vars["user"]
	host := vars["host"]
	port := vars["port"]
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	messageToVerify := user + "," + host + "," + port + "," + vars["expiry"] + "," + vars["encrypted_msg"]
	err := verify.CheckMAC(vars["mac"], messageToVerify, []byte(os.Getenv("SECRET")))
	if err != nil {
		return nil, err
	}
	decryptedMessage := conceal.Decrypt(vars["encrypted_msg"], "")
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
	priv, err := AuthMethod(kPair)
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
