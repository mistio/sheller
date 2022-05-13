package lxd

import (
	"encoding/json"
	"io"
	"sheller/util/secret/vault"
	"strconv"
	"strings"

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

func Control(conn *websocket.Conn, size TerminalSize) {
	msg := api.ContainerExecControl{}
	msg.Command = "window-resize"
	msg.Args = make(map[string]string)
	msg.Args["width"] = strconv.Itoa(size.Width)
	msg.Args["height"] = strconv.Itoa(size.Height)
	buf, _ := json.Marshal(msg)
	conn.WriteMessage(websocket.TextMessage, buf)
}

func DecodeResizeMessage(r io.Reader) TerminalSize {
	b := make([]byte, 1)
	resizeMessage := ""
	for {
		_, err := r.Read(b)
		if err == io.EOF {
			break
		}
		resizeMessage += string(b)
	}
	dec := json.NewDecoder(strings.NewReader(resizeMessage))
	var m TerminalSize
	dec.Decode(&m)
	return m
}
