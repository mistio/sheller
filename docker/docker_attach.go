package docker

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sheller/machine"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	shellerTLSUtil "sheller/util/tls"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type attachConnParameters struct {
	CA   string
	Cert string
	Key  string
	Host string
	Port string
}

type attachConnArgs struct {
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

var attachConnArguments *attachConnArgs
var tlsConfig *tls.Config

func prepareAttachConnectionParameters(vars map[string]string) (attachConnParameters, error) {
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return attachConnParameters{}, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	vault_addr := vault.SecretPath(plaintextParts[1])
	vault_secret_engine_path := vault.SecretPath(plaintextParts[2])
	key_path := vault.SecretPath(plaintextParts[3])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return attachConnParameters{}, err
	}
	secretPath := vault_addr + "/v1/" + vault_secret_engine_path + "/data/" + key_path
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return attachConnParameters{}, err
	}
	params := attachConnParameters{}
	if CA, exists := secretData["ca_cert_file"]; exists {
		CaCert, ok := CA.(string)
		if !ok {
			return attachConnParameters{}, errors.New("can't read ca certificate")
		}
		params.CA = CaCert
	}
	if cert, exists := secretData["cert_file"]; exists {
		ClientCert, ok := cert.(string)
		if !ok {
			return attachConnParameters{}, errors.New("can't read ca certificate")
		}
		params.Cert = ClientCert
	}
	if key, exists := secretData["key_file"]; exists {
		ClientKey, ok := key.(string)
		if !ok {
			return attachConnParameters{}, errors.New("can't read ca certificate")
		}
		params.Key = ClientKey
	}
	if host, exists := secretData["host"]; exists {
		Host, ok := host.(string)
		if !ok {
			return attachConnParameters{}, errors.New("can't read host")
		}
		params.Host = Host
	} else {
		return attachConnParameters{}, errors.New("host not found")
	}
	if port, exists := secretData["port"]; exists {
		Port, ok := port.(string)
		if !ok {
			return attachConnParameters{}, errors.New("can't read port")
		}
		params.Port = Port
	} else {
		return attachConnParameters{}, errors.New("port not found")
	}
	return params, nil
}

func attachRequest(args *attachConnArgs, opts *attachOptions) (*http.Request, error) {
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

func EstablishAttachIOWebsocket(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	params, err := prepareAttachConnectionParameters(vars)
	if err != nil {
		return nil, nil, err
	}
	machineID := vars["machineID"]
	attachConnArguments = &attachConnArgs{
		Host:      params.Host,
		Port:      params.Port,
		MachineID: machineID,
		Name:      vars["name"],
		Cluster:   vars["cluster"],
	}
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
	}
	if params.CA == "" && params.Cert == "" && params.Key == "" {
		attachConnArguments.Scheme = "http"
	} else {
		attachConnArguments.Scheme = "https"
		tlsConfig, err = shellerTLSUtil.CreateTLSConfig([]byte(params.Cert), []byte(params.Key), []byte(params.CA))
		if err != nil {
			return nil, nil, err
		}
		dialer.TLSClientConfig = tlsConfig
	}
	req, err := attachRequest(attachConnArguments, &attachOptions{
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

func ResizeAttachTerminal(size machine.TerminalSize) error {
	//create empty url to be populated
	u := &url.URL{}
	u.Scheme = attachConnArguments.Scheme
	u.Host = attachConnArguments.Host + ":" + attachConnArguments.Port
	u.Path = fmt.Sprintf("/containers/%s/resize", attachConnArguments.MachineID)
	resizeMessage := struct {
		H int `json:"h"`
		W int `json:"w"`
	}{H: size.Height, W: size.Width}
	resizeMessageJSON, err := json.Marshal(resizeMessage)
	if err != nil {
		return err
	}
	client := http.DefaultClient
	if tlsConfig != nil {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}
	_, err = client.Post(u.String(), "application/json", bytes.NewBuffer(resizeMessageJSON))
	if err != nil {
		return err
	}
	return nil
}
