package websocketLog

// Logs any application errors to a websocket connection
// apart from logging to the stdout.

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
zap.S().Error("some error")

*/

// Refer to log package
const (
	Ldate         = 1 << iota     // the date in the local time zone: 2009/01/23
	Ltime                         // the time in the local time zone: 01:23:23
	Lmicroseconds                 // microsecond resolution: 01:23:23.123123.  assumes Ltime.
	Llongfile                     // full file name and line number: /a/b/c/d.go:23
	Lshortfile                    // final file name element and line number: d.go:23. overrides Llongfile
	LUTC                          // if Ldate or Ltime is set, use UTC rather than the local time zone
	Lmsgprefix                    // move the "prefix" from the beginning of the line to before the message
	LstdFlags     = Ldate | Ltime // initial values for the standard logger
)

var (
	newline        = byte(10)
	carriageReturn = byte(13)
)

type WebsocketWriter struct {
	Conn *websocket.Conn
}

func (w *WebsocketWriter) Write(p []byte) (n int, err error) {
	err = w.Conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return len(p), err
	}
	err = w.Conn.WriteMessage(websocket.BinaryMessage, []byte{newline, carriageReturn})
	if err != nil {
		return len(p), err
	}
	return len(p), nil
}
func WrapLogger(w WebsocketWriter) *log.Logger {
	// io.MultiWriter: Each write is written to each
	// listed writer, one at a time.
	// If a listed writer returns an error, that overall
	// write operation stops and returns the error;
	// it does not continue down the list.
	log := log.New(io.MultiWriter(os.Stdout, &w), "", 1)
	log.SetFlags(LstdFlags | Lshortfile)
	return log
}
