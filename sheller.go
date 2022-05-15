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
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	sheller "sheller/lib"
	"sheller/machine"
	shellerio "sheller/util/io"
	"sheller/util/verify"
	"strconv"
	"sync"
	"time"

	"github.com/elliotchance/sshtunnel"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var (
	listen           = flag.String("listen", "127.0.0.1:8086", "Address to listen to.")
	dialTimeout      = flag.Duration("dial_timeout", 10*time.Second, "Dial timeout.")
	handshakeTimeout = flag.Duration("handshake_timeout", 10*time.Second, "Handshake timeout.")
	writeTimeout     = flag.Duration("write_timeout", 10*time.Second, "Write timeout.")
	pongTimeout      = flag.Duration("pong_timeout", 10*time.Second, "Pong message timeout.")
	// Send pings to peer with this period. Must be less than pongTimeout.
	pingPeriod = (*pongTimeout * 9) / 10
	cacheBuff  bytes.Buffer
	upgrader   websocket.Upgrader
)

func startSSH(session *ssh.Session) error {
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		return fmt.Errorf("request for pseudo terminal failed: %s", err)
	}

	// Start remote shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %s", err)
	}

	return nil
}

func clientToHostSSH(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, writer io.Writer, session *ssh.Session) {
	defer wg.Done()
	defer cancel()
	// websocket -> server
	conn.SetReadDeadline(time.Now().Add(*pongTimeout))
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := shellerio.GetNextReader(ctx, conn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		dataTypeBuf := make([]byte, 1)
		readBytes, err := r.Read(dataTypeBuf)
		if readBytes != 1 {
			log.Println("Unexpected number of bytes read")
			return
		}

		switch dataTypeBuf[0] {
		case 0:
			if _, err := io.Copy(writer, r); err != nil {
				log.Printf("Reading from websocket: %v", err)
				return
			}
		case 1:
			decoder := json.NewDecoder(r)
			resizeMessage := machine.TerminalSize{}
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				log.Println(err)
				return
			}
			session.WindowChange(resizeMessage.Height, resizeMessage.Width)
		}
	}
}

func hostToClient(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, reader io.Reader) {
	defer wg.Done()
	defer cancel()
	// server -> websocket
	// TODO: NextWriter() seems to be broken.
	if err := sheller.File2WS(ctx, cancel, reader, conn); err == io.EOF {
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(*writeTimeout)); err == websocket.ErrCloseSent {
		} else if err != nil {
			log.Printf("Error sending close message: %v", err)
		}
	} else if err != nil {
		log.Printf("Reading from file: %v", err)
	}
}

func clientToHost(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, writer io.Writer) {
	defer wg.Done()
	defer cancel()
	// websocket -> server
	conn.SetReadDeadline(time.Now().Add(*pongTimeout))
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := shellerio.GetNextReader(ctx, conn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}

		if _, err := io.Copy(writer, r); err != nil {
			log.Printf("Reading from websocket: %v", err)
			return
		}
	}
}

func pingWebsocket(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(*writeTimeout)); err != nil {
				log.Println("ping:", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func handleVNC(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	vars := mux.Vars(r)
	log.Print(vars)
	messageToVerify := vars["proxy"] + "," + vars["host"] + "," + vars["port"] + "," + vars["expiry"] + "," + vars["encrypted_msg"]
	err := verify.CheckMAC(vars["mac"], messageToVerify, []byte(os.Getenv("SECRET")))
	if err != nil {
		log.Print(err)
		return
	}
	priv, err := machine.Cfg(vars)
	if err != nil {
		log.Println(err)
	}
	// Setup the tunnel, but do not yet start it yet.
	tunnel := sshtunnel.NewSSHTunnel(
		// User and host of tunnel server, it will default to port 22
		// if not specified.
		vars["proxy"],
		priv, // 1. private key
		vars["host"]+":"+vars["port"],
		"0",
	)
	// You can provide a logger for debugging, or remove this line to
	// make it silent.
	// tunnel.Log = log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)
	// Start the server in the background. You will need to wait a
	// small amount of time for it to bind to the localhost port
	// before you can start sending connections.
	go tunnel.Start()
	time.Sleep(100 * time.Millisecond)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	s, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tunnel.Local.Port)), *dialTimeout)
	if err != nil {
		log.Println(err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go clientToHost(ctx, cancel, conn, &wg, s)
	go hostToClient(ctx, cancel, conn, &wg, s)
	go pingWebsocket(ctx, cancel, conn, &wg)

	wg.Wait()
	log.Println("VNC connection finished")
}

func handleSSH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	vars := mux.Vars(r)
	messageToVerify := vars["user"] + "," + vars["host"] + "," + vars["port"] + "," + vars["expiry"] + "," + vars["encrypted_msg"]
	err := verify.CheckMAC(vars["mac"], messageToVerify, []byte(os.Getenv("SECRET")))
	if err != nil {
		log.Print(err)
		return
	}
	priv, err := machine.Cfg(vars)
	if err != nil {
		fmt.Print(err)
	}
	config := &ssh.ClientConfig{
		User: vars["user"],
		Auth: []ssh.AuthMethod{
			priv,
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}
	connSSH, err := ssh.Dial("tcp", vars["host"]+":"+vars["port"], config)
	if err != nil {
		log.Println("Failed to dial: " + err.Error())
		return
	}
	defer connSSH.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := connSSH.NewSession()
	if err != nil {
		log.Println("Failed to create session: " + err.Error())
		return
	}
	defer session.Close()

	remoteStdin, err := session.StdinPipe()
	if err != nil {
		log.Println("Failed to create stdinpipe: " + err.Error())
		return
	}
	remoteStdout, err := session.StdoutPipe()
	if err != nil {
		log.Println("Failed to create stdoutpipe: " + err.Error())
		return
	}
	remoteStdout = shellerio.NewCancelableReader(ctx, remoteStdout)

	err = startSSH(session)
	if err != nil {
		log.Println(err)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(3)

	go clientToHostSSH(ctx, cancel, conn, &wg, remoteStdin, session)
	go hostToClient(ctx, cancel, conn, &wg, remoteStdout)
	go pingWebsocket(ctx, cancel, conn, &wg)

	wg.Wait()
	log.Println("SSH connection finished")
}

func main() {
	flag.Parse()

	upgrader = websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: *handshakeTimeout,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	log.Printf("sheller %s", sheller.Version)
	m := mux.NewRouter()
	m.HandleFunc("/ssh/{user}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleSSH)
	m.HandleFunc("/proxy/{proxy}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleVNC)
	s := &http.Server{
		Addr:           *listen,
		Handler:        m,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
