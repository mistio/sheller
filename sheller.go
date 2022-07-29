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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
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
	"sheller/util/stream"
	shellerTLSUtil "sheller/util/tls"
	"sheller/util/websocketIO"
	"sheller/util/websocketLog"
	"strconv"
	"sync"
	"time"

	"github.com/elliotchance/sshtunnel"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	// Main package
	// amqp 1.0 package to encode messages
	// messages interface package, you may not need to import it directly
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
	upgrader   websocket.Upgrader
)

const (
	dataMessage = iota
	resizeMessage
)

const (
	Kubernetes = iota
	Docker
	LXD
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

func handleLogsConsumer(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vars := mux.Vars(r)
	job_id := vars["job_id"]
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Print(err)
	}
	defer clientConn.Close()

	// Create a logger that logs any errors not only
	// to stdout but also reports any errors back
	// to the client through the websocket connection.
	WSLogger := websocketLog.WebsocketWriter{
		Conn: clientConn,
	}
	log := websocketLog.WrapLogger(WSLogger)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go stream.JobStreamConsumerWebsocket(ctx, cancel, job_id, clientConn, log)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	wg.Wait()
}

func handleKubernetes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	vars := mux.Vars(r)
	pod := vars["pod"]
	container := vars["container"]
	cluster := vars["cluster"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(pod + "," + container + "," + cluster + "," + vars["expiry"] + "," + vars["encrypted_msg"]))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != vars["mac"] {
		log.Println("HMAC mismatch")
		return
	}
	podConn, _, err := kubernetes.EstablishIOWebsocket(vars)
	if err != nil {
		log.Println(err)
		return
	}
	defer podConn.Close()
	wg := sync.WaitGroup{}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Print(err)
	}
	wg.Add(4)
	go websocketIO.ClientToHost(ctx, cancel, clientConn, &wg, podConn, nil, Kubernetes)
	go websocketIO.HostToClient(ctx, cancel, clientConn, &wg, podConn, Kubernetes)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, podConn, &wg)
	wg.Wait()
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
	resizer := docker.Terminal{
		Client:            client,
		TerminalResizeURI: TerminalResizeURI,
	}
	defer containerConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	go websocketIO.ClientToHost(ctx, cancel, clientConn, &wg, containerConn, &resizer, Docker)
	go websocketIO.HostToClient(ctx, cancel, clientConn, &wg, containerConn, Docker)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, containerConn, &wg)
	wg.Wait()
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
	var wg sync.WaitGroup
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer clientConn.Close()
	wg.Add(4)
	resizer := lxd.Terminal{
		ControlConn: controlConn,
	}
	go websocketIO.ClientToHost(ctx, cancel, clientConn, &wg, websocketStream, &resizer, LXD)
	go websocketIO.HostToClient(ctx, cancel, clientConn, &wg, websocketStream, LXD)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, websocketStream, &wg)
	wg.Wait()
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

func clientToHostSSH(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, writer io.Writer, resizer machine.Resizer) {
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
		case dataMessage:
			if _, err := io.Copy(writer, r); err != nil {
				log.Printf("Reading from websocket: %v", err)
				return
			}
		case resizeMessage:
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

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	WSLogger := websocketLog.WebsocketWriter{
		Conn: conn,
	}
	log := websocketLog.WrapLogger(WSLogger)

	vars := mux.Vars(r)
	user := vars["user"]
	host := vars["host"]
	port := vars["port"]
	mac := vars["mac"]
	command := vars["command"]
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(user + "," + host + "," + port + "," + vars["expiry"] + "," + command + "," + vars["encrypted_msg"]))
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

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		log.Printf("request for pseudo terminal failed: %s\n", err)
		return
	}
	decodedCommand, err := base64.StdEncoding.DecodeString(command)
	if err != nil {
		log.Println(err)
		return
	}
	if string(decodedCommand) == "default" {
		// Start remote shell
		if err := session.Shell(); err != nil {
			log.Printf("failed to start shell: %s\n", err)
			return
		}

	} else {

		err = session.Start(string(decodedCommand))
		if err != nil {
			log.Printf("failed to start with command: %s\n", err)
			return
		}

	}

	var wg sync.WaitGroup
	_, job_id_exists := vars["job_id"]
	if !job_id_exists {
		resizer := machine.Terminal{
			Session: session,
		}
		wg.Add(3)
		go clientToHostSSH(ctx, cancel, conn, &wg, remoteStdin, &resizer)
		go hostToClient(ctx, cancel, conn, &wg, remoteStdout)
		go pingWebsocket(ctx, cancel, conn, &wg)
		wg.Wait()
	} else {
		job_id := vars["job_id"]
		wg.Add(3)
		go clientToHost(ctx, cancel, conn, &wg, remoteStdin)
		go stream.HostProducer(ctx, cancel, conn, &wg, remoteStdout, job_id)
		go pingWebsocket(ctx, cancel, conn, &wg)
		wg.Wait()
	}
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
	log.SetFlags(log.LstdFlags | log.Lshortfile)

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
	m.HandleFunc("/stream/{job_id}", handleLogsConsumer)
	m.HandleFunc("/k8s-exec/{pod}/{container}/{cluster}/{expiry}/{encrypted_msg}/{mac}", handleKubernetes)
	m.HandleFunc("/docker-attach/{name}/{cluster}/{machineID}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleDocker)
	m.HandleFunc("/lxd-exec/{name}/{cluster}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleLXD)
	m.HandleFunc("/ssh/{user}/{host}/{port}/{expiry}/{command}/{encrypted_msg}/{mac}", handleSSH)
	// TODO:
	// Make job_id optional
	m.HandleFunc("/ssh/{user}/{host}/{port}/{expiry}/{command}/{encrypted_msg}/{mac}/{job_id}", handleSSH)
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
