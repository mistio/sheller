package sshIO

const packageName = "sshIO"

var (
	ErrWriteMessageToClient = packageName + ": failed writing websocket message to client"
	ErrReadMessageType      = packageName + ": failed to detect whether the client was sending data or attempting to resize the terminal"
	ErrReadClientMessage    = packageName + ": failed reading client's keystroke from websocket"
	ErrReadRemoteStdout     = packageName + ": failed reading from pipe that is connected to the standard output of the remote host"
	ErrWriteToRemoteStdin   = packageName + ": failed writing to pipe that is connected to the standard input of the remost host"
	ErrResizeTerminal       = packageName + ": failed resizing terminal"
	ErrSendCloseMessage     = packageName + ": failed sending websocket Close Message to client"
)
