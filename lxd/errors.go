package lxd

import "errors"

const packageName = "lxd"

var (
	ErrReadTLSServerCert                             = errors.New(packageName + ": reading TLS Server Certificate of remote server failed")
	ErrReadTLSClientCert                             = errors.New(packageName + ": reading TLS Client Certificate for client authentication failed")
	ErrReadTLSClientKey                              = errors.New(packageName + ": reading TLS Client Key for client authentication failed")
	ErrReadHost                                      = errors.New(packageName + ": reading host of remote server failed")
	ErrReadPort                                      = errors.New(packageName + ": reading port of remote server failed")
	ErrOperationMetadataInvalidFormat                = errors.New(packageName + ": operation metadata not in expected format")
	ErrWebsocketConnectionSecretInvalidFormat        = errors.New(packageName + ": secret of websocket connection that bridges pty not in expected format")
	ErrControlWebsocketConnectionSecretInvalidFormat = errors.New(packageName + ": secret ofcontrol websocket connection not in expected format")
)
