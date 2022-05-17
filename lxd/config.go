package lxd

import (
	"fmt"
	"log"
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
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return nil, err, nil
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	secretPath := vault.SecretPath(plaintextParts[1])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return nil, err, nil
	}
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return nil, err, nil
	}
	SecretWithTls, err := unmarshalSecret(secretData)
	if err != nil {
		log.Print(err)
		return nil, err, nil
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
