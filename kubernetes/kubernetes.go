package kubernetes

import (
	"fmt"
	"net/http"
	"net/url"
	"sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	"k8s.io/client-go/rest"
)

type execConfig struct {
	Namespace string
	Pod       string
	Container string
	Command   []string
	TTY       bool
	Stdin     bool
}

var kubeProtocols = []string{
	"v4.channel.k8s.io",
	"v3.channel.k8s.io",
	"v2.channel.k8s.io",
	"channel.k8s.io",
}

func EstablishIOWebsocket(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	command := strings.Fields(vars["command"])
	if len(command) == 0 {
		command = []string{"/bin/bash"}
	}
	opts := &execConfig{
		Namespace: "default",
		Pod:       vars["pod"], // pod name not the same as pod if more than one pod
		Container: vars["container"],
		Command:   command,
		Stdin:     true,
		TTY:       true,
	}
	decryptedMessage, err := conceal.Decrypt(vars["encrypted_msg"], "")
	if err != nil {
		return nil, nil, err
	}
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := vault.Token(plaintextParts[0])
	vault_addr := vault.SecretPath(plaintextParts[1])
	vault_secret_engine_path := vault.SecretPath(plaintextParts[2])
	key_path := vault.SecretPath(plaintextParts[3])
	expiry, err := strconv.ParseInt(vars["expiry"], 10, 64)
	if err != nil {
		return nil, nil, err
	}
	secretPath := vault_addr + "/v1/" + vault_secret_engine_path + "/data/" + key_path
	secretData, err := vault.GetSecret(token, secretPath, expiry)
	if err != nil {
		return nil, nil, err
	}
	secret, host, err := unmarshalSecret(secretData)
	if err != nil {
		return nil, nil, err
	}
	clientConfig := rest.Config{}
	clientConfig.Host = host
	clientConfig = secret.MergeWithConfig(clientConfig)
	req, err := execRequest(&clientConfig, opts)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := rest.TLSConfigFor(&clientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf(ErrKubernetesConfig+": %v\n", err)
	}
	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
		Subprotocols:    kubeProtocols,
	}
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		return nil, nil, fmt.Errorf(ErrConnectToPod+": %v\n", err)
	}
	return podConn, Response, err
}

func execRequest(config *rest.Config, opts *execConfig) (*http.Request, error) {
	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf(ErrInvalidURLFormat+": %v\n", err)
	}

	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf(ErrInvalidURLScheme+": %v\n", u.Scheme)
	}

	u.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec", opts.Namespace, opts.Pod)

	rawQuery := "stdout=true&tty=true"
	for _, c := range opts.Command {
		rawQuery += "&command=" + c
	}

	if opts.Container != "" {
		rawQuery += "&container=" + opts.Container
	}

	if opts.TTY {
		rawQuery += "&tty=true"
	}

	if opts.Stdin {
		rawQuery += "&stdin=true"
	}
	u.RawQuery = rawQuery
	Request := &http.Request{
		Host:   u.Host,
		Method: http.MethodGet,
		URL:    u,
	}
	if config.BearerToken != "" {
		Request.Header = http.Header{
			"authorization": {"Bearer " + config.BearerToken},
		}
	}
	return Request, nil
}
