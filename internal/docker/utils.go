package docker

import (
	"fmt"
	"net/http"
	"net/url"
	"sheller/util/secret/vault"
)

func unmarshalSecret(d vault.SecretData) (secretWithTls, error) {
	var secret secretWithTls
	secret.Tls.CA = d["ca_cert_file"]
	secret.Tls.Cert = d["cert_file"]
	secret.Tls.Key = d["key_file"]
	secret.Host = d["host"]
	secret.Port = d["port"]
	return secret, nil
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
		return nil, fmt.Errorf("Unrecognised URL scheme in %v", u)
	}

	u.Path = fmt.Sprintf("/containers/%s/attach/ws", opts.MachineID)
	u.RawQuery = "logs=1&stdin=1&stdout=1"
	// todo: enable customized options

	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
	}, nil
}
