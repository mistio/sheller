package vault

import "errors"

const packageName = "vault"

var (
	ErrEmptyToken            = errors.New(packageName + ": value of token is empty")
	ErrEmptySecretPath       = errors.New(packageName + ": value of SecretPath is empty")
	ErrInvalidResponseFormat = errors.New(packageName + ": secret data not in expected format")
	ErrSessionExpired        = errors.New(packageName + ": session expired")
)
