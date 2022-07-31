package machine

import "errors"

const packageName = "machine"

var (
	ErrReadPublicKey  = errors.New(packageName + ": reading public key of machine failed")
	ErrReadPrivateKey = errors.New(packageName + ": reading private key of machine failed")
)
