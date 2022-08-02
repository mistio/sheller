package lxd

import (
	"encoding/json"
	"errors"
	"fmt"
	"sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	lxd "github.com/lxc/lxd/client"
	"github.com/lxc/lxd/shared/api"
)

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

func PrepareConnectionParameters(vars map[string]string) (string, *lxd.ConnectionArgs, error) {
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return "", &lxd.ConnectionArgs{}, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	vault_addr := vault.SecretPath(plaintextParts[1])
	vault_secret_engine_path := vault.SecretPath(plaintextParts[2])
	key_path := vault.SecretPath(plaintextParts[3])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return "", &lxd.ConnectionArgs{}, err
	}
	secretPath := vault_addr + "/v1/" + vault_secret_engine_path + "/data/" + key_path
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return "", &lxd.ConnectionArgs{}, err
	}
	ConnArgs := &lxd.ConnectionArgs{}
	_, hasCaCert := secretData["ca_cert_file"]
	if hasCaCert {
		CaCert, ok := secretData["ca_cert_file"].(string)
		if !ok {
			return "", &lxd.ConnectionArgs{}, errors.New("can't read ca certificate")
		}
		ConnArgs.TLSCA = CaCert
	}
	ClientCert, ok := secretData["cert_file"].(string)
	if !ok {
		return "", &lxd.ConnectionArgs{}, errors.New("can't read client certificate")
	}
	ConnArgs.TLSClientCert = ClientCert
	ClientKey, ok := secretData["key_file"].(string)
	if !ok {
		return "", &lxd.ConnectionArgs{}, errors.New("can't read client key")
	}
	ConnArgs.TLSClientKey = ClientKey
	Host, ok := secretData["host"].(string)
	if !ok {
		return "", &lxd.ConnectionArgs{}, errors.New("can't read host")
	}
	Port, ok := secretData["port"].(string)
	if !ok {
		return "", &lxd.ConnectionArgs{}, errors.New("can't read port'")
	}

	url := fmt.Sprintf("https://%s:%s", Host, Port)
	return url, ConnArgs, nil
}
func EstablishIOWebsockets(vars map[string]string) (*websocket.Conn, *websocket.Conn, error) {
	url, ConnArgs, err := PrepareConnectionParameters(vars)
	if err != nil {
		return nil, nil, err
	}
	c, err := lxd.ConnectLXD(url, ConnArgs)
	if err != nil {
		return nil, nil, err
	}
	command := strings.Fields(vars["command"])
	if len(command) == 0 {
		command = []string{"/bin/bash"}
	}
	req := api.InstanceExecPost{
		Command:     command,
		Interactive: true,
		WaitForWS:   true,
	}

	op, err := c.ExecInstance(vars["name"], req, nil)
	if err != nil {
		return nil, nil, err
	}
	secretFDS := op.Get().Metadata["fds"]
	secret, ok := secretFDS.(map[string]any)
	if !ok {
		return nil, nil, errors.
			New("operation metadata not in expected format")
	}
	secret_0, ok := secret["0"].(string)
	if !ok {
		return nil, nil, errors.
			New("secret of websocket connection to bridge pty not in expected format")
	}
	secret_control, ok := secret["control"].(string)
	if !ok {
		return nil, nil, errors.
			New("secret of websocket control connection not in expected format")
	}
	websocketStream, err := c.GetOperationWebsocket(op.Get().ID, secret_0)
	if err != nil {
		return nil, nil, err
	}
	controlConn, err := c.GetOperationWebsocket(op.Get().ID, secret_control)
	if err != nil {
		return nil, nil, err
	}
	return websocketStream, controlConn, nil
}

type Terminal struct {
	ControlConn *websocket.Conn
}

func (t *Terminal) Resize(Height int, Width int) error {
	msg := api.ContainerExecControl{}
	msg.Command = "window-resize"
	msg.Args = make(map[string]string)
	msg.Args["width"] = strconv.Itoa(Width)
	msg.Args["height"] = strconv.Itoa(Height)
	buf, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	err = t.ControlConn.WriteMessage(websocket.TextMessage, buf)
	if err != nil {
		return err
	}
	return nil
}
