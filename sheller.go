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
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sheller/docker"
	"sheller/kubernetes"
	sheller "sheller/lib"
	"sheller/lxd"
	"sheller/machine"
	"sheller/util/cancelable"
	shellerTLSUtil "sheller/util/tls"
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
	pingPeriod     = (*pongTimeout * 9) / 10
	upgrader       websocket.Upgrader
	newline        = byte(10)
	carriageReturn = byte(13)
)

func init() {
	_, secretExists := os.LookupEnv("INTERNAL_KEYS_SECRET")
	_, signKeyExists := os.LookupEnv("INTERNAL_KEYS_SIGN")
	if secretExists && signKeyExists {
		return
	} else {
		INTERNAL_KEYS_SECRET_file, err := os.Open("secrets/secret.txt")
		if err != nil {
			log.Fatal(err)
		}
		INTERNAL_KEYS_SIGN_file, err := os.Open("secrets/sign.txt")
		if err != nil {
			log.Fatal(err)
		}
		secretString, err := ioutil.ReadAll(INTERNAL_KEYS_SECRET_file)
		if err != nil {
			log.Fatal(err)
		}
		signString, err := ioutil.ReadAll(INTERNAL_KEYS_SIGN_file)
		if err != nil {
			log.Fatal(err)
		}
		err = os.Setenv("INTERNAL_KEYS_SECRET", string(secretString))
		if err != nil {
			log.Fatal(err)
		}
		err = os.Setenv("INTERNAL_KEYS_SIGN", string(signString))
		if err != nil {
			log.Fatal(err)
		}
	}
}

func clientToPod(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, containerConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	clientConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	clientConn.SetPongHandler(func(string) error { clientConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	containerConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	containerConn.SetPongHandler(func(string) error { containerConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, clientConn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		dataTypeBuf := make([]byte, 100)
		_, err = r.Read(dataTypeBuf)
		if err != nil {
			log.Println(err)
		}
		switch dataTypeBuf[0] {
		case 0:
			data := dataTypeBuf[1:]
			dataLength := len(data)
			if dataLength == -1 {
				log.Println("failed to get the correct number of bytes read, ignoring message")
				continue
			}
			if bytes.Contains(data, []byte{newline}) {
				data = append(data, []byte{carriageReturn, newline}...)
			}
			err := containerConn.WriteMessage(websocket.BinaryMessage, data)
			if err != nil {
				log.Printf("failed to write %v bytes to tty: %s", len(data), err)
			}
		case 1:
			continue
		}
	}
}

func PodToClient(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, containerConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	for {
		r, err := sheller.GetNextReader(ctx, containerConn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			if err := clientConn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(*writeTimeout)); err == websocket.ErrCloseSent {
			} else if err != nil {
				log.Printf("Error sending close message: %v", err)
			}
			return
		}

		buf := make([]byte, 1024, 32*1024)
		readBytes, err := r.Read(buf)
		if err != nil {
			log.Println(err)
		}
		if readBytes > 1 {
			switch buf[0] {
			case 1, 2:
				buf[0] = 0
				clientConn.WriteMessage(websocket.BinaryMessage, buf[:readBytes])
			}
		}
	}
}

func handleKubernetes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	vars := mux.Vars(r)
	name := vars["name"]
	cluster := vars["cluster"]
	user := vars["user"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(name + "," + cluster + "," + user + "," + vars["expiry"] + "," + vars["encrypted_msg"]))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != vars["mac"] {
		log.Println("HMAC mismatch")
		return
	}
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Print(err)
	}
	podConn, Response, err := kubernetes.EstablishIOWebsocket(vars)
	if err != nil {
		body, err := io.ReadAll(Response.Body)
		bodyString := string(body)
		log.Print(bodyString)
		log.Println(err)
		return
	}
	defer podConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	go PodToClient(ctx, cancel, clientConn, podConn, &wg)
	go clientToPod(ctx, cancel, clientConn, podConn, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, podConn, &wg)
	wg.Wait()
}

func clientToContainerDocker(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, containerConn *websocket.Conn, client *http.Client, terminalResizeURI string, wg *sync.WaitGroup) {

	defer wg.Done()
	defer cancel()
	clientConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	clientConn.SetPongHandler(func(string) error { clientConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	containerConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	containerConn.SetPongHandler(func(string) error { containerConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, clientConn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		dataTypeBuf := make([]byte, 1)
		_, err = r.Read(dataTypeBuf)
		if err != nil {
			log.Println(err)
			return
		}
		switch dataTypeBuf[0] {
		case 0:
			keystroke := make([]byte, 1)
			dataLength, err := r.Read(keystroke)
			if err != nil {
				log.Println(err)
				return
			}
			if dataLength == -1 {
				log.Println("failed to get the correct number of bytes read, ignoring message")
				continue
			}
			err = containerConn.WriteMessage(websocket.BinaryMessage, keystroke)
			if err != nil {
				log.Printf("failed to write to tty: %s", err)
			}
		case 1:
			decoder := json.NewDecoder(r)
			resizeMessage := machine.TerminalSize{}
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				log.Println(err)
				return
			}
			err = docker.ResizeAttachedTerminal(client, terminalResizeURI, resizeMessage)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func handleDocker(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	cluster := vars["cluster"]
	machineID := vars["machineID"]
	host := vars["host"]
	port := vars["port"]
	encrypted_msg := vars["encrypted_msg"]
	mac := vars["mac"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(name + "," + cluster + "," + machineID + "," + host + "," + port + "," + vars["expiry"] + "," + encrypted_msg))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		log.Println("HMAC mismatch")
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print(err)
	}
	attachConnParameters, err := docker.PrepareAttachConnectionParameters(vars)
	if err != nil {
		log.Println(err)
		return
	}
	attachConnArguments := &docker.AttachConnArgs{
		Host:      attachConnParameters.Host,
		Port:      attachConnParameters.Port,
		MachineID: machineID,
		Name:      vars["name"],
		Cluster:   vars["cluster"],
	}
	tlsConfig := &tls.Config{}
	if attachConnParameters.Cert == "" && attachConnParameters.Key == "" {
		attachConnArguments.Scheme = "http"
	} else {
		attachConnArguments.Scheme = "https"
		tlsConfig, err = shellerTLSUtil.CreateTLSConfig([]byte(attachConnParameters.Cert), []byte(attachConnParameters.Key), []byte(attachConnParameters.CA))
		if err != nil {
			log.Println(err)
			return
		}
	}
	containerConn, _, err := docker.EstablishAttachIOWebsocket(&attachConnParameters, attachConnArguments, tlsConfig)
	if err != nil {
		log.Print(err)
		return
	}
	client := http.DefaultClient
	if tlsConfig != nil {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}
	TerminalResizeURI := fmt.Sprintf(
		"%s://%s:%s/containers/%s/resize",
		attachConnArguments.Scheme,
		attachConnArguments.Host,
		attachConnArguments.Port,
		attachConnArguments.MachineID)

	defer containerConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	go containerToClient(ctx, cancel, clientConn, containerConn, &wg)
	go clientToContainerDocker(ctx, cancel, clientConn, containerConn, client, TerminalResizeURI, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, containerConn, &wg)
	wg.Wait()
}

func clientToContainerLXD(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, containerConn *websocket.Conn, ControlConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	clientConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	clientConn.SetPongHandler(func(string) error { clientConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	containerConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	containerConn.SetPongHandler(func(string) error { containerConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, clientConn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		dataTypeBuf := make([]byte, 1)
		_, err = r.Read(dataTypeBuf)
		if err != nil {
			log.Println(err)
			return
		}
		switch dataTypeBuf[0] {
		case 0:
			keystroke := make([]byte, 1)
			dataLength, err := r.Read(keystroke)
			if err != nil {
				log.Println(err)
				return
			}
			if dataLength == -1 {
				log.Println("failed to get the correct number of bytes read, ignoring message")
				continue
			}
			err = containerConn.WriteMessage(websocket.BinaryMessage, keystroke)
			if err != nil {
				log.Printf("failed to write to tty: %s", err)
			}
		case 1:
			decoder := json.NewDecoder(r)
			resizeMessage := machine.TerminalSize{}
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				log.Println(err)
				return
			}
			err = lxd.ResizeTerminal(ControlConn, resizeMessage)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func containerToClient(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, containerConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	b := bytes.Buffer{}
	writer := bufio.NewWriter(&b)
	for {
		r, err := sheller.GetNextReader(ctx, containerConn)
		if err != nil {
			log.Println(err)
		}
		if r == nil {
			if err := clientConn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(*writeTimeout)); err == websocket.ErrCloseSent {
			} else if err != nil {
				log.Printf("Error sending close message: %v\n", err)
			}
			return
		}
		if _, err := io.Copy(writer, r); err != nil {
			log.Printf("Reading from websocket: %v", err)
			return
		}
		clientConn.WriteMessage(websocket.BinaryMessage, b.Bytes())
		b.Reset()
	}
}

func handleLXD(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	vars := mux.Vars(r)
	name := vars["name"]
	cluster := vars["cluster"]
	host := vars["host"]
	port := vars["port"]
	mac := vars["mac"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(name + "," + cluster + "," + host + "," + port + "," + vars["expiry"] + "," + vars["encrypted_msg"]))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		log.Println("HMAC mismatch")
		return
	}
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	// Use websocketStream to send commands and read results from
	// the terminal.
	// Use controlConn to send control characters to the terminal.
	websocketStream, controlConn, err := lxd.EstablishIOWebsockets(vars)
	if err != nil {
		log.Print(err)
		return
	}
	defer websocketStream.Close()
	defer controlConn.Close()
	defer clientConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	go containerToClient(ctx, cancel, clientConn, websocketStream, &wg)
	go clientToContainerLXD(ctx, cancel, clientConn, websocketStream, controlConn, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, websocketStream, &wg)
	wg.Wait()
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

func clientToHostSSH(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, writer io.Writer, session *ssh.Session) {
	defer wg.Done()
	defer cancel()
	// websocket -> server
	conn.SetReadDeadline(time.Now().Add(*pongTimeout))
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, conn)
		if err != nil {
			log.Println(err)
			return
		}
		if r == nil {
			return
		}
		dataTypeBuf := make([]byte, 1)
		readBytes, err := r.Read(dataTypeBuf)
		if err != nil {
			log.Println(err)
			return
		}
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

func clientToHost(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, writer io.Writer) {
	defer wg.Done()
	defer cancel()
	// websocket -> server
	conn.SetReadDeadline(time.Now().Add(*pongTimeout))
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := sheller.GetNextReader(ctx, conn)
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

func handleSSH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	vars := mux.Vars(r)
	user := vars["user"]
	host := vars["host"]
	port := vars["port"]
	mac := vars["mac"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(user + "," + host + "," + port + "," + vars["expiry"] + "," + vars["encrypted_msg"]))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		log.Println("HMAC mismatch")
		return
	}

	priv, err := machine.GetPrivateKey(vars)
	if err != nil {
		log.Println(err)
		return
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			priv,
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	connSSH, err := ssh.Dial("tcp", host+":"+port, config)
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
	remoteStdout = cancelable.NewCancelableReader(ctx, remoteStdout)

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

func handleVNC(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	vars := mux.Vars(r)
	proxy := vars["proxy"]
	host := vars["host"]
	port := vars["port"]
	mac := vars["mac"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(proxy + "," + host + "," + port + "," + vars["expiry"] + "," + vars["encrypted_msg"]))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		log.Println("HMAC mismatch")
		return
	}

	priv, err := machine.GetPrivateKey(vars)
	if err != nil {
		log.Println(err)
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
	tunnel.Log = log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)
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
	m.HandleFunc("/k8s-exec/{name}/{cluster}/{user}/{expiry}/{encrypted_msg}/{mac}", handleKubernetes)
	m.HandleFunc("/docker-attach/{name}/{cluster}/{machineID}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleDocker)
	m.HandleFunc("/lxd-exec/{name}/{cluster}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleLXD)
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
