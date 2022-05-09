package lxd

import (
	"encoding/json"
	"sheller/util/secret/vault"
	"strconv"

	"github.com/gorilla/websocket"
	"github.com/lxc/lxd/shared/api"
)

func unmarshalSecret(d vault.SecretData) (secretWithTls, error) {
	var secret secretWithTls
	secret.Cert = d["cert_file"]
	secret.Key = d["key_file"]
	secret.Host = d["host"]
	secret.Port = d["port"]
	return secret, nil
}

func Control(conn *websocket.Conn, width, height int) {
	msg := api.ContainerExecControl{}
	msg.Command = "window-resize"
	msg.Args = make(map[string]string)
	msg.Args["width"] = strconv.Itoa(width)
	msg.Args["height"] = strconv.Itoa(height)
	buf, _ := json.Marshal(msg)
	conn.WriteMessage(websocket.TextMessage, buf)
}
