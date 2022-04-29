package docker

import "sheller/util/tls"

type secretWithTls struct {
	Tls  tls.Tls
	Host string
	Port string
}
