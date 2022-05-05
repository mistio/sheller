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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sheller/internal/docker"
	k8s "sheller/internal/kubernetes"
	"sheller/internal/lxd"
	"sheller/internal/machine"
	sheller "sheller/lib"
	conceal "sheller/util/conceal"
	shellerio "sheller/util/io"
	"sheller/util/secret/vault"
	"strconv"
	"strings"
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

var (
	newline        = []byte{10}
	carriageReturn = []byte{13}
	delete         = []byte{127}
	up             = []byte{27, 91, 65}
	down           = []byte{27, 91, 66}
	right          = []byte{27, 91, 67}
	left           = []byte{27, 91, 68}
)

const (
	stdin = iota
	stdout
	stderr
)

func handleLXD(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Print(vars)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print(err)
	}
	cacheBuff.Write([]byte{0})
	containerConn, err := lxd.Cfg(vars)
	if err != nil {
		log.Print(err)
		return
	}
	defer containerConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	// reaches here but does nothing inside the goroutines below
	go hostToClientContainer(ctx, cancel, clientConn, containerConn, &wg)
	go clientToHostContainer(ctx, cancel, clientConn, containerConn, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, containerConn, &wg)
	wg.Wait()
}

func handleDocker(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Print(vars)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print(err)
	}
	cacheBuff.Write([]byte{0})
	containerConn, _, err := docker.Cfg(vars)
	if err != nil {
		log.Print(err)
		return
	}
	defer containerConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	// reaches here but does nothing inside the goroutines below
	go hostToClientContainer(ctx, cancel, clientConn, containerConn, &wg)
	go clientToHostContainer(ctx, cancel, clientConn, containerConn, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, containerConn, &wg)
	wg.Wait()
}

func hostToClientContainer(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, containerConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	for {
		msgtype, msg, err := containerConn.ReadMessage()
		if err != nil {
			log.Print(err)
		}
		fmt.Print(msgtype)
		fmt.Print(msg)

		r, err := shellerio.GetNextReader(ctx, containerConn)
		if err != nil {
			if err := clientConn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(*writeTimeout)); err == websocket.ErrCloseSent {
			} else if err != nil {
				log.Printf("Error sending close message: %v", err)
			}
			return
		}
		if r == nil {
			return
		}
		var buf []byte
		buf = make([]byte, 1024, 10*1024)
		readBytes, err := r.Read(buf)
		if err != nil {
			log.Println(err)
		}
		log.Printf("%s", cacheBuff.String())
		if readBytes > 1 {
			switch buf[0] {
			case 1:
				buf[0] = 0
				s := strings.Replace(string(buf[1:]), cacheBuff.String(), "", -1)
				clientConn.WriteMessage(websocket.BinaryMessage, []byte(s))
			}
			cacheBuff.Reset()
			cacheBuff.Write([]byte{0})
		}
	}
}

func clientToHostContainer(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, containerConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	clientConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	clientConn.SetPongHandler(func(string) error { clientConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	containerConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	containerConn.SetPongHandler(func(string) error { containerConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := shellerio.GetNextReader(ctx, clientConn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		dataTypeBuf := make([]byte, 2)
		_, err = r.Read(dataTypeBuf)
		switch dataTypeBuf[0] {
		case 0:
			data := dataTypeBuf[1:]
			dataLength := len(data)
			if dataLength == -1 {
				log.Println("failed to get the correct number of bytes read, ignoring message")
				continue
			}
			if bytes.Contains(data, newline) {
				cacheBuff.Write(carriageReturn)
				cacheBuff.Write(newline)
			} else {
				cacheBuff.Write(data)
			}
			err := containerConn.WriteMessage(websocket.BinaryMessage, cacheBuff.Bytes())
			if err != nil {
				log.Printf("failed to write %v bytes to tty: %s", len(data), err)
			}
			cacheBuff.Reset()
			cacheBuff.Write([]byte{0})
		case 1:
			continue
		}
	}
}

func handleKubernetes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Print(err)
	}
	cacheBuff.Write([]byte{0})
	vars := mux.Vars(r)
	podConn, _, err := k8s.Cfg(vars)
	if err != nil {
		log.Println(err)
		return
	}
	defer podConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	go hostToClientContainer(ctx, cancel, clientConn, podConn, &wg)
	go clientToHostContainer(ctx, cancel, clientConn, podConn, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, podConn, &wg)
	wg.Wait()
}

func handleSSH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	vars := mux.Vars(r)
	config, err := machine.SHHCfg(vars)
	if err != nil {
		fmt.Print(err)
	}
	connSSH, err := ssh.Dial("tcp", vars["host"]+":"+vars["port"], config)
	if err != nil {
		log.Println("Failed to dial: " + err.Error())
		/*
			err := saveFailedAttemptKeyMachineAssociation(client, keyMachineAssociationID)
			if err != nil {
				log.Println("Failed to save failed attempt on KeyMachineAssociation: " + err.Error())
			}
		*/
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
	proxy := vars["proxy"]
	keyID := vars["key"]
	host := vars["host"]
	port := vars["port"]
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	mac := vars["mac"]
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))
	// Write Data to it
	h.Write([]byte(proxy + "," + keyID + "," + host + "," + port + "," + vars["expiry"]))
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		panic("HMAC MISMATCH")
	}
	decryptedMessage := conceal.Decrypt(vars["encrypted_msg"], "")
	plaintextParts := strings.SplitN(decryptedMessage, ",", -1)
	token := plaintextParts[0]
	secretPath := plaintextParts[1]
	keyName := plaintextParts[2]
	vaultConfig := vault.AccessWithToken{
		Vault: vault.Vault{
			Address:    os.Getenv("VAULT_ADDR"),
			SecretPath: fmt.Sprintf("/v1/%s/data/mist/keys/%s", secretPath, keyName),
		},
		Token: token,
	}
	secretData, err := vault.SecretRequest(vaultConfig, expiry)
	if err != nil {
		log.Println(err)
		return
	}
	kPair, err := machine.UnmarshalSecret(secretData)
	if err != nil {
		log.Println(err)
		return
	}
	priv, err := machine.AuthMethod(kPair)
	if err != nil {
		log.Println(err)
		return
	}
	// Setup the tunnel, but do not yet start it yet.
	tunnel := sshtunnel.NewSSHTunnel(
		// User and host of tunnel server, it will default to port 22
		// if not specified.
		proxy,
		priv, // 1. private key
		host+":"+port,
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
	m.HandleFunc("/lxd-exec/{name}/{cluster}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleLXD)
	m.HandleFunc("/k8s-exec/{name}/{cluster}/{user}/{expiry}/{encrypted_msg}/{mac}", handleKubernetes)
	m.HandleFunc("/docker-exec/{name}/{cluster}/{host}/{port}/{user}/{expiry}/{encrypted_msg}/{mac}", handleDocker)
	m.HandleFunc("/ssh/{user}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleSSH)
	m.HandleFunc("/proxy/{proxy}/{key}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleVNC)
	s := &http.Server{
		Addr:           *listen,
		Handler:        m,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
