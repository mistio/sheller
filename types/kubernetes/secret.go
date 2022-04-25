package kubernetes

type Tls struct {
	CA   string
	Cert string
	Key  string
}

type SecretWithTls struct {
	Tls  Tls
	Host string
	Port string
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
