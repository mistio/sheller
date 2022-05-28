// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package lib

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/gorilla/websocket"
)

const (
	Version = "0.01"
)

func File2WS(ctx context.Context, cancel func(), src io.Reader, dst *websocket.Conn) error {
	defer cancel()
	for {
		if ctx.Err() != nil {
			return nil
		}
		b := make([]byte, 32*1024)
		if n, err := src.Read(b); err != nil {
			return err
		} else {
			b = b[:n]
		}
		//log.Printf("->ws %d bytes: %q", len(b), string(b))
		if err := dst.WriteMessage(websocket.BinaryMessage, b); err != nil {
			log.Println(err)
			return err
		}
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
		b := make([]byte, 1)
		r.Read(b)
		if b[0] == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("Non binary message")
	}
	return r, nil
}
