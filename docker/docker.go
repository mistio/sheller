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

type connParameters struct {
	CA   string
	Cert string
	Key  string
	Host string
	Port string
}

type connectionArgs struct {
	Scheme    string
	Host      string
	Port      string
	MachineID string
	Name      string
	Cluster   string
}

type attachOptions struct {
	logs   bool
	stream bool
	stdin  bool
	stdout bool
	stderr bool
}

func PrepareConnectionParameters(vars map[string]string) (connParameters, error) {
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return connParameters{}, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	vault_addr := vault.SecretPath(plaintextParts[1])
	vault_secret_engine_path := vault.SecretPath(plaintextParts[2])
	key_path := vault.SecretPath(plaintextParts[3])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return connParameters{}, err
	}
	secretPath := vault_addr + "/v1/" + vault_secret_engine_path + "/data/" + key_path
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return connParameters{}, err
	}
	params := connParameters{}
	if CA, exists := secretData["ca_cert_file"]; exists {
		CaCert, ok := CA.(string)
		if !ok {
			return connParameters{}, errors.New("can't read ca certificate")
		}
		params.CA = CaCert
	}
	if cert, exists := secretData["cert_file"]; exists {
		ClientCert, ok := cert.(string)
		if !ok {
			return connParameters{}, errors.New("can't read ca certificate")
		}
		params.Cert = ClientCert
	}
	if key, exists := secretData["key_file"]; exists {
		ClientKey, ok := key.(string)
		if !ok {
			return connParameters{}, errors.New("can't read ca certificate")
		}
		params.Cert = ClientKey
	}
	if host, exists := secretData["host"]; exists {
		Host, ok := host.(string)
		if !ok {
			return connParameters{}, errors.New("can't read host")
		}
		params.Host = Host
	} else {
		return connParameters{}, errors.New("host not found")
	}
	if port, exists := secretData["host"]; exists {
		Port, ok := port.(string)
		if !ok {
			return connParameters{}, errors.New("can't read host")
		}
		params.Port = Port
	} else {
		return connParameters{}, errors.New("port not found")
	}
	return params, nil
}

func EstablishIOWebsocket(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	params, err := PrepareConnectionParameters(vars)
	if err != nil {
		return nil, nil, err
	}
	machineID := vars["machineID"]
	opts := &connectionArgs{
		Host:      params.Host,
		Port:      params.Port,
		MachineID: machineID,
		Name:      vars["name"],
		Cluster:   vars["cluster"],
	}
	if params.CA == "" && params.Cert == "" && params.Key == "" {
		opts.Scheme = "http"
	} else {
		opts.Scheme = "https"
	}
	cfg, err := tls.CreateTLSConfig([]byte(params.Cert), []byte(params.Key), []byte(params.CA))
	if err != nil {
		return nil, nil, err
	}
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  cfg,
	}
	req, err := attachRequest(opts, &attachOptions{
		logs:   true,
		stream: true,
		stdin:  true,
		stdout: true,
		stderr: true,
	})
	if err != nil {
		return nil, nil, err
	}
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		return nil, nil, err
	}
	return podConn, Response, nil
}

func attachRequest(args *connectionArgs, opts *attachOptions) (*http.Request, error) {
	//create empty url to be populated
	u := &url.URL{}
	u.Scheme = args.Scheme
	u.Host = args.Host + ":" + args.Port
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("unrecognised URL scheme in %v", u)
	}

	u.Path = fmt.Sprintf("/containers/%s/attach/ws", args.MachineID)
	rawQuery := "stdout=true&tty=true"
	if opts.logs {
		rawQuery += "&logs=true"
	}
	if opts.stream {
		rawQuery += "&stream=true"
	}
	if opts.stdin {
		rawQuery += "&stdin=true"
	}
	if opts.stdout {
		rawQuery += "&stdout=true"
	}
	if opts.stderr {
		rawQuery += "&stderr=true"
	}
	u.RawQuery = rawQuery
	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
	}, nil
}
