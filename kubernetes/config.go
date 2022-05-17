package kubernetes

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"

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

func PodConnection(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	name := vars["name"]
	opts := &execConfig{
		Namespace: "default",
		Pod:       name, // pod name not the same as pod if more than one pod
		Container: name,
		Command:   []string{"/bin/bash"},
		Stdin:     true,
		TTY:       true,
	}
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	decryptedMessage := conceal.Decrypt(vars["encrypted_msg"], "")
	vaultConfig := vault.CreateVaultAccessWithToken(decryptedMessage)
	secretData, err := vault.SecretRequest(vaultConfig, expiry)
	if err != nil {
		return nil, nil, err
	}
	secret, host, err := unmarshalSecret(secretData)
	if err != nil {
		return nil, nil, err
	}
	clientConfig := rest.Config{}
	clientConfig.Host = string(host)
	clientConfig, err = secret.MergeWithConfig(clientConfig)
	if err != nil {
		log.Println(err)
	}
	req, err := execRequest(&clientConfig, opts)
	if err != nil {
		log.Fatalln(err)
	}
	tlsConfig, err := rest.TLSConfigFor(&clientConfig)
	if err != nil {
		log.Println(err)
	}
	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
		Subprotocols:    kubeProtocols,
	}
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		log.Println(err)
	}
	return podConn, Response, err
}

func execRequest(config *rest.Config, opts *execConfig) (*http.Request, error) {
	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("unrecognised URL scheme in %v", u)
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

	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
	}, nil
}

func (info Info) MergeWithConfig(c rest.Config) (rest.Config, error) {
	var config = c
	config.Username = info.User
	config.Password = info.Password
	config.CAFile = info.CAFile
	config.CertFile = info.CertFile
	config.KeyFile = info.KeyFile
	config.BearerToken = info.BearerToken
	if info.Insecure != nil {
		config.Insecure = *info.Insecure
	}
	return config, nil
}
