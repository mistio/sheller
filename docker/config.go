package docker

import (
	"net/http"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	tls "sheller/util/tls"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type attachOptions struct {
	Host      string
	Port      string
	MachineID string
	Name      string
	Cluster   string
}

func Cfg(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	machineID := vars["machineID"]
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return nil, nil, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	secretPath := vault.SecretPath(plaintextParts[1])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return nil, nil, err
	}
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return nil, nil, err
	}
	SecretWithTls, err := unmarshalSecret(secretData)
	if err != nil {
		return nil, nil, err
	}
	opts := &attachOptions{
		Host:      SecretWithTls.Host,
		Port:      SecretWithTls.Port,
		MachineID: machineID,
		Name:      vars["name"],
		Cluster:   vars["cluster"],
	}
	cfg, err := tls.CreateTLSConfig([]byte(SecretWithTls.Tls.Cert), []byte(SecretWithTls.Tls.Key), []byte(SecretWithTls.Tls.CA))
	if err != nil {
		return nil, nil, err
	}
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  cfg,
	}
	req, err := attachRequest(opts)
	if err != nil {
		return nil, nil, err
	}
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		return nil, nil, err
	}
	return podConn, Response, nil
}
