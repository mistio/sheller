package lxd

import (
	"fmt"
	"log"
	"os"
	"sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	lxd "github.com/lxc/lxd/client"
	"github.com/lxc/lxd/shared/api"
)

type ConnectionArgs lxd.ConnectionArgs

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

func Cfg(vars map[string]string) (*websocket.Conn, error, *websocket.Conn) {
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	decryptedMessage := conceal.Decrypt(vars["encrypted_msg"], "")
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := plaintextParts[0]
	secretPath := plaintextParts[1]
	keyName := plaintextParts[2]
	LXDSecretsURI := fmt.Sprintf("/v1/%s/data/mist/clouds/%s", secretPath, keyName)
	vaultConfig := vault.AccessWithToken{
		Vault: vault.Vault{
			Address:    os.Getenv("VAULT_ADDR"),
			SecretPath: LXDSecretsURI,
		},
		Token: token,
	}
	secretData, err := vault.SecretRequest(vaultConfig, expiry)
	if err != nil {
		log.Print(err)
	}
	SecretWithTls, err := unmarshalSecret(secretData)
	if err != nil {
		log.Print(err)
	}
	ConnArgs := &lxd.ConnectionArgs{
		TLSClientCert:      SecretWithTls.Cert,
		TLSClientKey:       SecretWithTls.Key,
		InsecureSkipVerify: true,
	}
	// use host:port as the address
	url := fmt.Sprintf("https://%s:%s", SecretWithTls.Host, SecretWithTls.Port)
	c, err := lxd.ConnectLXD(url, ConnArgs)
	if err != nil {
		log.Print(err)
	}

	// Setup the exec request
	// not sure about environment
	req := api.ContainerExecPost{
		Command:     []string{"/bin/bash"},
		Interactive: true,
		WaitForWS:   true,
		//Environment: map[string]string{"TERM": "xterm"},
	}

	op, err := c.ExecContainer(vars["name"], req, nil)

	// Setup the exec requestconnStdin
	if err != nil {
		log.Print(err)
	}
	secretFDS := op.Get().Metadata["fds"]
	// convert secret to map[string]string
	secret, ok := secretFDS.(map[string]any)
	if !ok {
		log.Print(err)
	}
	secret_0 := secret["0"].(string)
	conn, err := c.GetOperationWebsocket(op.Get().ID, secret_0)
	secret_control := secret["control"].(string)
	ControlConn, _ := c.GetOperationWebsocket(op.Get().ID, secret_control)
	return conn, err, ControlConn
}
