package vault

type Vault struct {
	Address    string
	SecretPath string
}

type AccessWithToken struct {
	Vault
	Token string
}
