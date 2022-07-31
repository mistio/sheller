package websocketIO

const packageName = "websocketIO"

var (
	ErrWriteMessageToClient = packageName + ": writing websocket message to client failed"
	ErrReadMessageType      = packageName + ": failed to detect whether the client was sending data or attempting to resize the terminal"
	ErrReadClientMessage    = packageName + ": reading client's keystroke from websocket failed"
	ErrReadHostMessage      = packageName + ": reading host's websocket message failed"
	ErrWriteToHost          = packageName + ": writing websocket message to host failed"
	ErrResizeTerminal       = packageName + ": resizing terminal failed"
	ErrSendCloseMessage     = packageName + ": sending websocket Close Message to client failed"
)
