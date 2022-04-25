package docker

type DockerdTls struct {
	CA   string
	Cert string
	Key  string
}

type SecretWithTls struct {
	Tls  DockerdTls
	Host string
	Port string
}
