package docker

import "errors"

const packageName = "docker"

var (
	ErrReadCA    = errors.New(packageName + ": reading CA Certificate of docker host failed")
	ErrReadCert  = errors.New(packageName + ": reading Client Certificate for client authentication failed")
	ErrReadKey   = errors.New(packageName + ": reading Client Key for client authentication failed")
	ErrReadHost  = errors.New(packageName + ": reading host of docker daemon failed")
	ErrReadPort  = errors.New(packageName + ": reading port of kubernetes hosts failed")
	ErrEmptyHost = errors.New(packageName + ": value of host is empty")
	ErrEmptyPort = errors.New(packageName + ": value of port is empty")
)

var (
	ErrInvalidURLScheme   = packageName + ": invalid URL scheme"
	ErrInvalidURLFormat   = packageName + ": invalid URL format"
	ErrConnectToContainer = packageName + ": failed to open websocket connection with docker host's requested container"
)
