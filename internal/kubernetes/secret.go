package kubernetes

import "sheller/util/tls"

type secretWithTls struct {
	Tls  tls.Tls
	Host string
	Port string
	// user string
	// context string
}

/*
TO-DO: support other ways to authenticate with kubernetes clusters
ex. username,password
type UserPass struct {
	User string
	Password string
}
type VaultUserPassSecret struct {
	UserPass UserPass
	Host string
	Port string
}
*/
