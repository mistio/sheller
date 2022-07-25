package websocketIO

import (
	"bufio"
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
	Kubernetes = iota
	Docker
	LXD
)

const (
	dataMessage = iota
	resizeMessage
)

func writeToHost(ctx context.Context, cancel func(), src *websocket.Conn, dst *websocket.Conn, hostType int) error {
	defer cancel()
	for {
		r, err := sheller.GetNextReader(ctx, src)
		if err != nil {
			log.Println(err)
		}
		b := make([]byte, 32*1024)
		if n, err := r.Read(b); err != nil {
			return err
		} else {
			b = b[:n]
		}
		if hostType == Kubernetes {
			if b[0] == 0 {
				continue
			} else {
				b = b[1:]
			}
		}
		if err := dst.WriteMessage(websocket.BinaryMessage, b); err != nil {
			log.Println(err)
			return err
		}
	}
}

func ClientToHost(ctx context.Context, cancel context.CancelFunc, client *websocket.Conn, wg *sync.WaitGroup, host *websocket.Conn, resizer machine.Resizer, hostType int) {
	defer wg.Done()
	defer cancel()
	client.SetReadDeadline(time.Now().Add(pongTimeout))
	client.SetPongHandler(func(string) error { client.SetReadDeadline(time.Now().Add(pongTimeout)); return nil })
	host.SetReadDeadline(time.Now().Add(pongTimeout))
	host.SetPongHandler(func(string) error { client.SetReadDeadline(time.Now().Add(pongTimeout)); return nil })
	b := bytes.Buffer{}
	writer := bufio.NewWriter(&b)
	for {
		r, err := sheller.GetNextReader(ctx, client)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		r = bufio.NewReader(r)
		messageType := make([]byte, 1)
		if _, err := r.Read(messageType); err != nil {
			log.Println(err)
		}
		switch messageType[0] {
		case dataMessage:
			if _, err := io.Copy(writer, r); err != nil {
				log.Printf("Reading from websocket: %v", err)
				return
			}
			var data []byte
			if hostType == Kubernetes {
				data = append([]byte{0}, b.Bytes()...)
				if bytes.Contains(data, []byte{newline}) {
					data = append(data, []byte{carriageReturn, newline}...)
				}
			} else {
				data = b.Bytes()
			}
			err = host.WriteMessage(websocket.BinaryMessage, data)
			if err != nil {
				log.Printf("failed to write to tty: %s", err)
			}
			b.Reset()
		case resizeMessage:
			if resizer != nil {
				decoder := json.NewDecoder(r)
				resizeMessage := machine.TerminalSize{}
				err := decoder.Decode(&resizeMessage)
				if err != nil {
					log.Println(err)
					return
				}
				resizer.Resize(resizeMessage)
			}
		}
	}
}

func HostToClient(ctx context.Context, cancel context.CancelFunc, client *websocket.Conn, wg *sync.WaitGroup, host *websocket.Conn, hostType int) {
	defer wg.Done()
	defer cancel()
	if err := writeToHost(ctx, cancel, client, host, hostType); err == io.EOF {
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
