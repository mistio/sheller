package sshIO

import (
	"context"
	"encoding/json"
	"io"
	sheller "sheller/lib"
	"sheller/machine"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	pongTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
)

const (
	dataMessage = iota
	resizeMessage
)

func ForwardClientMessageToHostOrResize(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, resizer machine.Resizer, writer io.Writer) {
	defer wg.Done()
	defer cancel()
	// websocket -> server
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, conn)
		if err != nil {
			zap.S().Error(err)
			return
		}

		if r == nil {
			return
		}

		dataTypeBuf := make([]byte, 1)
		_, err = r.Read(dataTypeBuf)
		if err != nil {
			zap.S().Error(err)
			return
		}

		switch dataTypeBuf[0] {
		case dataMessage:
			if _, err := io.Copy(writer, r); err != nil {
				zap.S().Infof("Reading from websocket: %v", err)
				return
			}
		case resizeMessage:
			decoder := json.NewDecoder(r)
			resizeMessage := machine.TerminalSize{}
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				zap.S().Error(err)
				return
			}
			err = resizer.Resize(resizeMessage.Height, resizeMessage.Width)
			if err != nil {
				zap.S().Error(err)
				return
			}
		}

	}
}

func ForwardHostMessageToClient(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, reader io.Reader) {
	defer wg.Done()
	defer cancel()
	// server -> websocket
	// TODO: NextWriter() seems to be broken.
	if err := sheller.File2WS(ctx, cancel, reader, conn); err == io.EOF {
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeTimeout)); err == websocket.ErrCloseSent {
		} else if err != nil {
			zap.S().Warnf("Error sending close message: %v", err)
		}
	} else if err != nil {
		zap.S().Infof("Reading from file: %v", err)
	}
}

func ForwardClientMessageToHost(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, writer io.Writer) {
	defer wg.Done()
	defer cancel()
	// websocket -> server
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, conn)
		if err != nil {
			zap.S().Error(err)
			return
		}

		if r == nil {
			return
		}

		if _, err := io.Copy(writer, r); err != nil {
			zap.S().Infof("Reading from websocket: %v", err)
			return
		}
	}
}
