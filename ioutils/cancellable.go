package ioutils

import (
	"context"
	"fmt"
	"io"

	"github.com/gorilla/websocket"
)

type CancelableReader struct {
	ctx  context.Context
	data chan []byte
	err  error
	r    io.Reader
}

func (c *CancelableReader) begin() {
	buf := make([]byte, 1024)
	for {
		n, err := c.r.Read(buf)
		if err != nil {
			c.err = err
			close(c.data)
			return
		}
		tmp := make([]byte, n)
		copy(tmp, buf[:n])
		c.data <- tmp
	}
}

func (c *CancelableReader) Read(p []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case d, ok := <-c.data:
		if !ok {
			return 0, c.err
		}
		copy(p, d)
		return len(d), nil
	}
}

func GetNextReader(ctx context.Context, conn *websocket.Conn) (io.Reader, error) {
	mt, r, err := conn.NextReader()
	if ctx.Err() != nil {
		return nil, nil
	}
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,   // Normal.
		websocket.CloseAbnormalClosure, // OpenSSH killed proxy client.
	) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("nextreader: %v", err)
	}
	if mt != websocket.BinaryMessage {
		return nil, fmt.Errorf("Non binary message")
	}
	return r, nil
}

func NewCancelableReader(ctx context.Context, r io.Reader) *CancelableReader {
	c := &CancelableReader{
		r:    r,
		ctx:  ctx,
		data: make(chan []byte),
	}
	go c.begin()
	return c
}
