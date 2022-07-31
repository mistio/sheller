package websocketIO

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	sheller "sheller/lib"
	"sheller/machine"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	newline        = byte(10)
	carriageReturn = byte(13)
)

const (
	pongTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
)

const (
	dataMessage = iota
	resizeMessage
)

type Resizer interface {
	Resize(Height int, Width int) error
}

func ForwardClientMessageToHostOrResize(ctx context.Context, cancel context.CancelFunc, client *websocket.Conn, wg *sync.WaitGroup, host *websocket.Conn, resizer machine.Resizer, appendByte bool) {
	defer wg.Done()
	defer cancel()
	client.SetPongHandler(func(string) error { client.SetReadDeadline(time.Now().Add(pongTimeout)); return nil })
	host.SetPongHandler(func(string) error { client.SetReadDeadline(time.Now().Add(pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, client)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		messageType := make([]byte, 1)
		if _, err := r.Read(messageType); err != nil {
			log.Println(err)
			return
		}
		switch messageType[0] {
		case dataMessage:
			data := make([]byte, 1)
			_, err := r.Read(data)
			if err != nil {
				log.Println(err)
				return
			}
			if appendByte {
				data = append([]byte{0}, data...)
				if bytes.Contains(data, []byte{newline}) {
					data = append(data, []byte{carriageReturn, newline}...)
				}
			}
			err = host.WriteMessage(websocket.BinaryMessage, data)
			if err != nil {
				log.Printf("failed to write to tty: %s", err)
				return
			}
		case resizeMessage:
			if resizer != nil {
				decoder := json.NewDecoder(r)
				resizeMessage := machine.TerminalSize{}
				err := decoder.Decode(&resizeMessage)
				if err != nil {
					log.Println(err)
					return
				}
				err = resizer.Resize(resizeMessage.Height, resizeMessage.Width)
				if err != nil {
					log.Println(err)
					return
				}
			}
		}
	}
}

func ForwardHostMessageToClient(ctx context.Context, cancel context.CancelFunc, client *websocket.Conn, wg *sync.WaitGroup, host *websocket.Conn, appendedByte bool) {
	defer wg.Done()
	defer cancel()
	if err := writeToClient(ctx, cancel, host, client, appendedByte); err == io.EOF {
		if err := client.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeTimeout)); err == websocket.ErrCloseSent {
		} else if err != nil {
			log.Printf("Error sending close message: %v", err)
		}
	} else if err != nil {
		log.Printf("Reading from file: %v", err)
	}
}

func writeToClient(ctx context.Context, cancel func(), host *websocket.Conn, client *websocket.Conn, appendedByte bool) error {
	defer cancel()
	for {
		r, err := sheller.GetNextReader(ctx, host)
		if err != nil {
			log.Println(err)
		}
		if r == nil {
			return nil
		}
		b := make([]byte, 32*1024)
		if n, err := r.Read(b); err != nil {
			return err
		} else {
			b = b[:n]
		}
		if appendedByte {
			if b[0] == 0 {
				continue
			} else {
				b = b[1:]
			}
		}
		if err := client.WriteMessage(websocket.BinaryMessage, b); err != nil {
			log.Println(err)
			return err
		}
	}
}
