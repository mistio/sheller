package kubernetes

import (
	"flag"
	"log"
	"net/http"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"

	"github.com/gorilla/websocket"
	"k8s.io/client-go/rest"
)

type kubeTLSConfigTemplate struct {
	Certificate_authority_data string
	Server                     string
	Cluster                    string
	User                       string
	Context_name               string
	Client_certificate_data    string
	Client_key_data            string
}

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

type Info struct {
	User        string
	Password    string `datapolicy:"password"`
	CAFile      string
	CertFile    string
	KeyFile     string
	BearerToken string `datapolicy:"token"`
	Insecure    *bool
}

var kubeconfig string

func parseKubeConfig() {
	flag.StringVar(&kubeconfig, "kubeconfig", "config", "absolute path to the kubeconfig file")
	flag.Parse()
}

func Cfg(vars map[string]string) (*websocket.Conn, *http.Response, error) {
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
	SecretWithTls, err := unmarshalSecret(secretData)
	if err != nil {
		return nil, nil, err
	}
	info := Info{}
	info.CAFile = SecretWithTls.Tls.CA
	info.CertFile = SecretWithTls.Tls.Cert
	info.KeyFile = SecretWithTls.Tls.Key
	clientConfig := rest.Config{}
	clientConfig.Host = SecretWithTls.Host + ":" + SecretWithTls.Port
	clientConfig, err = info.MergeWithConfig(clientConfig)
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
