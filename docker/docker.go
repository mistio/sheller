package docker

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	"sheller/util/tls"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type secret struct {
	CA   string
	Cert string
	Key  string
	Host string
	Port string
}

type attachOptions struct {
	Host      string
	Port      string
	MachineID string
	Name      string
	Cluster   string
}

func PrepareConnectionParameters(vars map[string]string) (secret, error) {
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return secret{}, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	vault_addr := vault.SecretPath(plaintextParts[1])
	vault_secret_engine_path := vault.SecretPath(plaintextParts[2])
	key_path := vault.SecretPath(plaintextParts[3])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return secret{}, err
	}
	secretPath := vault_addr + "/v1/" + vault_secret_engine_path + "/data/" + key_path
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return secret{}, err
	}
	CaCert, ok := secretData["ca_cert_file"].(string)
	if !ok {
		return secret{}, errors.New("can't read ca certificate")
	}
	ClientCert, ok := secretData["cert_file"].(string)
	if !ok {
		return secret{}, errors.New("can't read client certificate")
	}
	ClientKey, ok := secretData["key_file"].(string)
	if !ok {
		return secret{}, errors.New("can't read client key")
	}
	Host, ok := secretData["host"].(string)
	if !ok {
		return secret{}, errors.New("can't read host")
	}
	Port, ok := secretData["port"].(string)
	if !ok {
		return secret{}, errors.New("can't read port'")
	}
	return secret{
		CA:   CaCert,
		Cert: ClientCert,
		Key:  ClientKey,
		Host: Host,
		Port: Port,
	}, nil
}

func EstablishIOWebsocket(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	secret, err := PrepareConnectionParameters(vars)
	if err != nil {
		return nil, nil, err
	}
	machineID := vars["machineID"]
	opts := &attachOptions{
		Host:      secret.Host,
		Port:      secret.Port,
		MachineID: machineID,
		Name:      vars["name"],
		Cluster:   vars["cluster"],
	}
	cfg, err := tls.CreateTLSConfig([]byte(secret.Cert), []byte(secret.Key), []byte(secret.CA))
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
func attachRequest(opts *attachOptions) (*http.Request, error) {
	//create empty url to be populated
	u := &url.URL{}
	u.Scheme = "https"
	u.Host = opts.Host + ":" + opts.Port
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("unrecognised URL scheme in %v", u)
	}

	u.Path = fmt.Sprintf("/containers/%s/attach/ws", opts.MachineID)
	u.RawQuery = "logs=1&stdin=1&stdout=1"
	// todo: enable customized options

	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
	}, nil
}
