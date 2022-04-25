package kubernetes

type KubeTLSConfigTemplate struct {
	Certificate_authority_data string
	Server                     string
	Cluster                    string
	User                       string
	Context_name               string
	Client_certificate_data    string
	Client_key_data            string
}

type ExecConfig struct {
	Namespace string
	Pod       string
	Container string
	Command   []string
	TTY       bool
	Stdin     bool
}

// todo: this should be in a file called "config.tmpl"
var Kube_tls_config_template string = `apiVersion: v1
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
var KubeProtocols = []string{
	"v4.channel.k8s.io",
	"v3.channel.k8s.io",
	"v2.channel.k8s.io",
	"channel.k8s.io",
}
