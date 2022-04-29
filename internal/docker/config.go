package docker

import (
	"fmt"
	"net/http"
	"os"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	tls "sheller/util/tls"
	"sheller/util/verify"
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
	name := vars["name"]
	cluster := vars["cluster"]
	host := vars["host"]
	port := vars["port"]
	encrypted_msg := vars["encrypted_msg"]
	mac := vars["mac"]
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	messageToVerify := name + "," + cluster + "," + host + "," + port + "," + vars["user"] + "," + vars["expiry"] + "," + encrypted_msg
	err := verify.CheckMAC(mac, messageToVerify, []byte(os.Getenv("SECRET")))
	if err != nil {
		return nil, nil, err
	}
	decryptedMessage := conceal.Decrypt(vars["encrypted_msg"], "")
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := plaintextParts[0]
	secretPath := plaintextParts[1]
	keyName := plaintextParts[2]
	machineID := plaintextParts[3]
	dockerSecretsURI := fmt.Sprintf("/v1/%s/data/mist/clouds/%s", secretPath, keyName)
	vaultConfig := vault.AccessWithToken{
		Vault: vault.Vault{
			Address:    os.Getenv("VAULT_ADDR"),
			SecretPath: dockerSecretsURI,
		},
		Token: token,
	}
	secretData, err := vault.SecretRequest(vaultConfig, expiry)
	if err != nil {
		return nil, nil, err
	}
	SecretWithTls, err := unmarshalSecret(secretData)
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
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		return nil, nil, err
	}
	return podConn, Response, nil
}
