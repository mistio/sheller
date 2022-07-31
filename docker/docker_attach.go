package docker

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type AttachConnParameters struct {
	CA   string
	Cert string
	Key  string
	Host string
	Port string
}

type AttachConnArgs struct {
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

type TerminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

func PrepareAttachConnectionParameters(vars map[string]string) (AttachConnParameters, error) {
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return AttachConnParameters{}, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	vault_addr := vault.SecretPath(plaintextParts[1])
	vault_secret_engine_path := vault.SecretPath(plaintextParts[2])
	key_path := vault.SecretPath(plaintextParts[3])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return AttachConnParameters{}, err
	}
	secretPath := vault_addr + "/v1/" + vault_secret_engine_path + "/data/" + key_path
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return AttachConnParameters{}, err
	}
	params := AttachConnParameters{}
	if CA, exists := secretData["ca_cert_file"]; exists {
		CaCert, ok := CA.(string)
		if !ok {
			return AttachConnParameters{}, ErrReadCA
		}
		params.CA = CaCert
	}
	if cert, exists := secretData["cert_file"]; exists {
		ClientCert, ok := cert.(string)
		if !ok {
			return AttachConnParameters{}, ErrReadCert
		}
		params.Cert = ClientCert
	}
	if key, exists := secretData["key_file"]; exists {
		ClientKey, ok := key.(string)
		if !ok {
			return AttachConnParameters{}, ErrReadKey
		}
		params.Key = ClientKey
	}
	if host, exists := secretData["host"]; exists {
		Host, ok := host.(string)
		if !ok {
			return AttachConnParameters{}, ErrReadHost
		}
		params.Host = Host
	} else {
		return AttachConnParameters{}, ErrEmptyHost
	}
	if port, exists := secretData["port"]; exists {
		Port, ok := port.(string)
		if !ok {
			return AttachConnParameters{}, ErrReadPort
		}
		params.Port = Port
	} else {
		return AttachConnParameters{}, ErrEmptyPort
	}
	return params, nil
}

func attachRequest(args *AttachConnArgs, opts *attachOptions) (*http.Request, error) {
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
		return nil, fmt.Errorf(ErrInvalidURLScheme+": %v\n", u.Scheme)
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

func EstablishAttachIOWebsocket(params *AttachConnParameters, args *AttachConnArgs, tlsConfig *tls.Config) (*websocket.Conn, *http.Response, error) {
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,
		TLSClientConfig:  tlsConfig,
	}
	req, err := attachRequest(args, &attachOptions{
		logs:   true,
		stream: true,
		stdin:  true,
		stdout: true,
		stderr: true,
	})
	if err != nil {
		return nil, nil, err
	}
	containerConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		return nil, nil, fmt.Errorf(ErrConnectToContainer+": %v\n", err)
	}
	return containerConn, Response, nil
}

type Terminal struct {
	Client            *http.Client
	TerminalResizeURI string
}

func (t *Terminal) Resize(Height int, Width int) error {
	resizeMessage := struct {
		H int `json:"h"`
		W int `json:"w"`
	}{H: Height, W: Width}
	resizeMessageJSON, err := json.Marshal(resizeMessage)
	if err != nil {
		return err
	}
	_, err = t.Client.Post(t.TerminalResizeURI, "application/json", bytes.NewBuffer(resizeMessageJSON))
	if err != nil {
		return err
	}
	return nil
}
