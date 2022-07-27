package websocketLog

import (
	"io"
	"log"
	"os"

	"github.com/gorilla/websocket"
)

/*

// How to use websocketLog package:
WSWriter := websocketLog.WebsocketWriter{
    conn: clientConn,
}
log := websocketLog.WrapLogger(WSWriter)
log.Println("some error")

*/

type WebsocketWriter struct {
	Conn *websocket.Conn
}

func (w *WebsocketWriter) Write(p []byte) (n int, err error) {
	err = w.Conn.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}
func WrapLogger(w WebsocketWriter) *log.Logger {
	// io.MultiWriter: Each write is written to each
	// listed writer, one at a time.
	// If a listed writer returns an error, that overall
	// write operation stops and returns the error;
	// it does not continue down the list.
	return log.New(io.MultiWriter(os.Stdout, &w), "", 1)
}
