package kubernetes

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sheller/util/secret/vault"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

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

func unmarshalSecret(d vault.SecretData) (secretWithTls, error) {
	var secret secretWithTls
	// todo:check if format of tls data is existent and correct
	// and return any possible errors
	secret.Tls.CA = b64.StdEncoding.EncodeToString([]byte(d["ca_cert_file"]))
	secret.Tls.Cert = b64.StdEncoding.EncodeToString([]byte(d["cert_file"]))
	secret.Tls.Key = b64.StdEncoding.EncodeToString([]byte(d["key_file"]))
	secret.Host = d["host"]
	secret.Port = d["port"]
	return secret, nil
}

func checkifPodExists(client *kubernetes.Clientset, opts *execConfig) error {
	pod, err := client.CoreV1().Pods(opts.Namespace).Get(context.TODO(), opts.Pod, metav1.GetOptions{})
	if pod.Status.Phase == "Running" {
		return nil
	}
	return err
}
