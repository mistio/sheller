package config

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	cryptoSheller "sheller/crypto"
	"sheller/secret"
	"strconv"
	"strings"
	"text/template"

	k8s "sheller/types/kubernetes"
	"sheller/types/vault"

	"github.com/gorilla/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var kubeconfig string

func parseKubeConfig() {
	flag.StringVar(&kubeconfig, "kubeconfig", "config", "absolute path to the kubeconfig file")
	flag.Parse()
}

func checkifPodExists(client *kubernetes.Clientset, opts *k8s.ExecConfig) error {
	pod, err := client.CoreV1().Pods(opts.Namespace).Get(context.TODO(), opts.Pod, metav1.GetOptions{})
	if pod.Status.Phase == "Running" {
		return nil
	}
	return err
}

func kubernetesExecRequest(config *rest.Config, opts *k8s.ExecConfig) (*http.Request, error) {
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
		return nil, fmt.Errorf("Unrecognised URL scheme in %v", u)
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

func KubernetesCfg(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	name := vars["name"]
	cluster := vars["cluster"]
	user := vars["user"]
	encrypted_msg := vars["encrypted_msg"]
	opts := &k8s.ExecConfig{
		Namespace: "default",
		Pod:       name,
		Container: name,
		Command:   []string{"/bin/bash"},
		Stdin:     true,
		TTY:       true,
	}
	mac := vars["mac"]
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	h.Write([]byte(name + "," + cluster + "," + user + "," + vars["expiry"] + "," + encrypted_msg))
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		return nil, nil, errors.New("Invalid MAC")
	}
	decryptedMessage := cryptoSheller.Decrypt(vars["encrypted_msg"], "")
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := plaintextParts[0]
	secretPath := plaintextParts[1]
	keyName := plaintextParts[2]
	kubernetesSecretsURI := fmt.Sprintf("/v1/%s/data/mist/clouds/%s", secretPath, keyName)

	vault := vault.AccessWithToken{
		Vault: vault.Vault{
			Address:    os.Getenv("VAULT_ADDR"),
			SecretPath: kubernetesSecretsURI,
		},
		Token: token,
	}
	KubernetesSecretWithTls, err := secret.KubernetesSecretWithTlsRequest(vault, expiry)
	if err != nil {
		return nil, nil, err
	}

	configTemplate := k8s.KubeTLSConfigTemplate{
		Certificate_authority_data: KubernetesSecretWithTls.Tls.CA,
		Server:                     "https://" + KubernetesSecretWithTls.Host + ":" + KubernetesSecretWithTls.Port,
		User:                       vars["user"],
		Cluster:                    "kubernetes",
		Context_name:               vars["user"] + "@" + "kubernetes",
		Client_certificate_data:    KubernetesSecretWithTls.Tls.Cert,
		Client_key_data:            KubernetesSecretWithTls.Tls.Key,
	}
	configFile, err := os.Create("kubeconfig.txt")
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	defer configFile.Close()
	var temp *template.Template
	// read kube_config string
	temp, err = template.New("").Parse(k8s.Kube_tls_config_template)
	err = temp.Execute(configFile, configTemplate)
	if err != nil {
		log.Fatalln(err)
	}
	parseKubeConfig()
	config, err := clientcmd.BuildConfigFromFlags("", "kubeconfig.txt")
	if err != nil {
		log.Fatalln(err)
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	err = checkifPodExists(clientSet, opts)
	if err != nil {
		panic(err.Error())
	}
	req, err := kubernetesExecRequest(config, opts)
	if err != nil {
		log.Fatalln(err)
	}
	// create an http post request

	tlsConfig, err := rest.TLSConfigFor(config)
	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
		Subprotocols:    k8s.KubeProtocols,
	}
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		log.Println(err)
	}
	return podConn, Response, err
}
