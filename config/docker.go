package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	cryptoSheller "sheller/crypto"
	"sheller/secret"
	"sheller/types/docker"
	"sheller/types/vault"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func DockerExecRequest(opts *docker.AttachOptions) (*http.Request, error) {
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

func DockerCfg(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	name := vars["name"]
	cluster := vars["cluster"]
	host := vars["host"]
	port := vars["port"]
	encrypted_msg := vars["encrypted_msg"]
	mac := vars["mac"]
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	h.Write([]byte(name + "," + cluster + "," + host + "," + port + "," + vars["user"] + "," + vars["expiry"] + "," + encrypted_msg))
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		return nil, nil, errors.New("Invalid MAC")
	}
	decryptedMessage := cryptoSheller.Decrypt(vars["encrypted_msg"], "")
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := plaintextParts[0]
	secretPath := plaintextParts[1]
	keyName := plaintextParts[2]
	machineID := plaintextParts[3]
	dockerSecretsURI := fmt.Sprintf("/v1/%s/data/mist/clouds/%s", secretPath, keyName)
	vault := vault.AccessWithToken{
		Vault: vault.Vault{
			Address:    os.Getenv("VAULT_ADDR"),
			SecretPath: dockerSecretsURI,
		},
		Token: token,
	}
	DockerSecretWithTls, err := secret.DockerSecretWithTlsRequest(vault, expiry)
	opts := &docker.AttachOptions{
		Host:      DockerSecretWithTls.Host,
		Port:      DockerSecretWithTls.Port,
		MachineID: machineID,
		Name:      vars["name"],
		Cluster:   vars["cluster"],
	}
	cert, err := tls.X509KeyPair([]byte(DockerSecretWithTls.Tls.Cert), []byte(DockerSecretWithTls.Tls.Key))
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(DockerSecretWithTls.Tls.CA))
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 2 * time.Second,

		TLSClientConfig: cfg,
	}
	req, err := DockerExecRequest(opts)
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		return nil, nil, err
	}
	return podConn, Response, nil
}
