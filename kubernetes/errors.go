package kubernetes

import "errors"

const packageName = "kubernetes"

var (
	ErrReadCA             = errors.New(packageName + ": reading CA Certificate of kubernetes cluster failed")
	ErrReadCert           = errors.New(packageName + ": reading Client Certificate for client authentication failed")
	ErrReadKey            = errors.New(packageName + ": reading Client Key for client authentication failed")
	ErrReadHost           = errors.New(packageName + ": reading host of kubernetes cluster failed")
	ErrReadPort           = errors.New(packageName + ": reading port of kubernetes cluster failed")
	ErrEmptyHost          = errors.New(packageName + ": value of host is empty")
	ErrEmptyPort          = errors.New(packageName + ": value of port is empty")
	ErrReadBearerToken    = errors.New(packageName + ": reading bearer token of kubernetes cluster failed")
	ErrInvalidCredentials = errors.New(packageName + ": insufficient credentials used for authentication")
)

var (
	ErrKubernetesConfig = packageName + ": creating a kubernetes-client config failed"
	ErrInvalidURLScheme = packageName + ": invalid URL scheme"
	ErrInvalidURLFormat = packageName + ": invalid URL format"
	ErrConnectToPod     = packageName + ": failed to open websocket connection with cluster's requested pod"
)
