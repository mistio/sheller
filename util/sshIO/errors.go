package sshIO

const packageName = "sshIO"

var (
	ErrWriteMessageToClient = packageName + ": writing websocket message to client failed"
	ErrReadMessageType      = packageName + ": failed to detect whether the client was sending data or attempting to resize the terminal "
	ErrReadClientMessage    = packageName + ": reading client's keystroke from websocket failed"
	ErrReadRemoteStdout     = packageName + ": reading from pipe that is connected to the standard output of the remote host failed"
	ErrWriteToRemoteStdin   = packageName + ": writing to pipe that is connected to the standard input of the remost host failed"
	ErrResizeTerminal       = packageName + ": resizing terminal failed"
	ErrSendCloseMessage     = packageName + ": sending websocket Close Message to client failed"
)
