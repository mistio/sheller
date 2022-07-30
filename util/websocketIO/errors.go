package websocketIO

const packageName = "websocketIO"

var (
	ErrWriteMessageToClient = packageName + ": failed writing websocket message to client"
	ErrReadMessageType      = packageName + ": failed to detect whether the client was sending data or attempting to resize the terminal"
	ErrReadClientMessage    = packageName + ": failed reading client's keystroke from websocket"
	ErrReadHostMessage      = packageName + ": failed reading host's websocket message"
	ErrWriteToHost          = packageName + ": failed writing websocket message to host"
	ErrResizeTerminal       = packageName + ": failed resizing terminal"
	ErrSendCloseMessage     = packageName + ": failed sending websocket Close Message to client"
)
