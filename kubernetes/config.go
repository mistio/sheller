package kubernetes

import (
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	conceal "sheller/util/conceal"
	"sheller/util/secret/vault"
	"strconv"

	"github.com/gorilla/websocket"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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

// todo: this should be in a file called "config.tmpl"
var kube_tls_config_template string = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {{.Certificate_authority_data}}
    server: {{.Server}}
  name: {{.Cluster}}
contexts:
- context:
    cluster: {{.Cluster}}
    user: {{.User}}
  name: {{.Context_name}}
current-context: {{.Context_name}}
kind: Config
preferences: {}
users:
- name: {{.User}}
  user:
    client-certificate-data: {{.Client_certificate_data}}
    client-key-data: {{.Client_key_data}}
`
var kubeProtocols = []string{
	"v4.channel.k8s.io",
	"v3.channel.k8s.io",
	"v2.channel.k8s.io",
	"channel.k8s.io",
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
	configTemplate := kubeTLSConfigTemplate{
		Certificate_authority_data: SecretWithTls.Tls.CA,
		Server:                     "https://" + SecretWithTls.Host + ":" + SecretWithTls.Port,
		User:                       vars["user"],
		Cluster:                    "kubernetes",
		Context_name:               vars["user"] + "@" + "kubernetes",
		Client_certificate_data:    SecretWithTls.Tls.Cert,
		Client_key_data:            SecretWithTls.Tls.Key,
	}
	configFile, err := os.Create("kubeconfig.txt")
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	defer configFile.Close()
	var temp *template.Template
	// read kube_config string
	temp, err = template.New("").Parse(kube_tls_config_template)
	err = temp.Execute(configFile, configTemplate)
	if err != nil {
		log.Fatalln(err)
	}
	parseKubeConfig()
	config, err := clientcmd.BuildConfigFromFlags("", "kubeconfig.txt")
	if err != nil {
		log.Fatalln(err)
	}
	req, err := execRequest(config, opts)
	if err != nil {
		log.Fatalln(err)
	}
	// create an http post request

	tlsConfig, err := rest.TLSConfigFor(config)
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
