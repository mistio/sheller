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
	sshIO "sheller/util/sshIO"
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
	"go.uber.org/zap"

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
	pingPeriod = (*pongTimeout * 2) / 10
	upgrader   websocket.Upgrader
)

func init() {
	logger, _ := zap.NewDevelopment() // .NewProduction()
	zap.ReplaceGlobals(logger)
	defer logger.Sync()
	zap.S().Infof("sheller %s", sheller.Version)
	zap.S().Info("Loading keys")
	_, secretExists := os.LookupEnv("INTERNAL_KEYS_SECRET")
	_, signKeyExists := os.LookupEnv("INTERNAL_KEYS_SIGN")
	if secretExists && signKeyExists {
		return
	} else {
		INTERNAL_KEYS_SECRET_file, err := os.Open("secrets/secret.txt")
		if err != nil {
			zap.S().Fatal(err)
		}
		INTERNAL_KEYS_SIGN_file, err := os.Open("secrets/sign.txt")
		if err != nil {
			zap.S().Fatal(err)
		}
		secretString, err := ioutil.ReadAll(INTERNAL_KEYS_SECRET_file)
		if err != nil {
			zap.S().Fatal(err)
		}
		signString, err := ioutil.ReadAll(INTERNAL_KEYS_SIGN_file)
		if err != nil {
			zap.S().Fatal(err)
		}
		err = os.Setenv("INTERNAL_KEYS_SECRET", string(secretString))
		if err != nil {
			zap.S().Fatal(err)
		}
		err = os.Setenv("INTERNAL_KEYS_SIGN", string(signString))
		if err != nil {
			zap.S().Fatal(err)
		}
	}
	zap.S().Info("Finished loading keys")
}

func handleJob(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]
	zap.S().Infof("Handling new job %s", jobID)
	decoder := json.NewDecoder(r.Body)
	var p machine.SSHRequest
	err := decoder.Decode(&p)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		zap.S().Warnw("Job returning bad request")
		zap.S().Error(err)
	} else {
		w.WriteHeader(http.StatusOK)
		zap.S().Info("Job returning OK")
		go runScript(jobID, p)
	}
	zap.S().Info("Finished job handler")
}

func runScript(jobID string, req machine.SSHRequest) {
	ctx := context.Background()
	zap.S().Infow("Starting runScript")
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(req.User + "," + req.Hostname + "," + req.Port + "," + req.Expiry + "," + req.CommandEncoded + "," + req.EncryptedMSG))
	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != req.Mac {
		zap.S().Error("HMAC mismatch")
		return
	}

	priv, err := machine.GetPrivateKey(req.EncryptedMSG, req.Expiry)
	if err != nil {
		zap.S().Error(err)
		return
	}

	config := &ssh.ClientConfig{
		User: req.User,
		Auth: []ssh.AuthMethod{
			priv,
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	connSSH, err := ssh.Dial("tcp", req.Hostname+":"+req.Port, config)
	if err != nil {
		zap.S().Error("Failed to dial: " + err.Error())
		return
	}
	defer connSSH.Close()
	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := connSSH.NewSession()
	if err != nil {
		zap.S().Error("Failed to create session: " + err.Error())
		return
	}
	defer session.Close()
	remoteStdout, err := session.StdoutPipe()
	if err != nil {
		zap.S().Error("Failed to create stdoutpipe: " + err.Error())
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
		zap.S().Errorf("request for pseudo terminal failed: %s\n", err)
		return
	}

	decodedCommand, err := base64.RawURLEncoding.WithPadding('=').DecodeString(req.CommandEncoded)
	if err != nil {
		zap.S().Error(err)
		return
	}
	zap.S().Infof("Decoded command: %s", decodedCommand)

	err = session.Start(string(decodedCommand))
	if err != nil {
		zap.S().Errorf("failed to start with command: %s\n", err)
		return
	}
	zap.S().Info("Session started")

	stream.HostProducer(ctx, remoteStdout, jobID)
	zap.S().Infow("Producing logs")

	session.Wait()
	zap.S().Infow("Finished runScript")
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
		zap.S().Error("HMAC mismatch")
		return
	}
	podConn, _, err := kubernetes.EstablishIOWebsocket(vars)
	if err != nil {
		zap.S().Error(err)
		return
	}
	defer podConn.Close()
	wg := sync.WaitGroup{}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Print(err)
	}
	wg.Add(4)
	go websocketIO.ForwardClientMessageToHostOrResize(ctx, cancel, clientConn, &wg, podConn, nil, true)
	go websocketIO.ForwardHostMessageToClient(ctx, cancel, clientConn, &wg, podConn, true)
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
		zap.S().Error("HMAC mismatch")
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		zap.S().Error(err)
	}
	attachConnParameters, err := docker.PrepareAttachConnectionParameters(vars)
	if err != nil {
		zap.S().Error(err)
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
			zap.S().Error(err)
			return
		}
	}
	containerConn, _, err := docker.EstablishAttachIOWebsocket(&attachConnParameters, attachConnArguments, tlsConfig)
	if err != nil {
		zap.S().Error(err)
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
	go websocketIO.ForwardClientMessageToHostOrResize(ctx, cancel, clientConn, &wg, containerConn, &resizer, false)
	go websocketIO.ForwardHostMessageToClient(ctx, cancel, clientConn, &wg, containerConn, false)
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
		zap.S().Error("HMAC mismatch")
		return
	}

	// Use websocketStream to send commands and read results from
	// the terminal.
	// Use controlConn to send control characters to the terminal.
	websocketStream, controlConn, err := lxd.EstablishIOWebsockets(vars)
	if err != nil {
		zap.S().Error(err)
		return
	}
	defer websocketStream.Close()
	defer controlConn.Close()
	var wg sync.WaitGroup
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		zap.S().Error(err)
		return
	}
	defer clientConn.Close()
	wg.Add(4)
	resizer := lxd.Terminal{
		ControlConn: controlConn,
	}
	go websocketIO.ForwardClientMessageToHostOrResize(ctx, cancel, clientConn, &wg, websocketStream, &resizer, false)
	go websocketIO.ForwardHostMessageToClient(ctx, cancel, clientConn, &wg, websocketStream, false)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, websocketStream, &wg)
	wg.Wait()
}

func handleSSH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		zap.S().Error(err)
		return
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Time{})

	vars := mux.Vars(r)
	p := machine.SSHRequest{
		User:           vars["user"],
		Hostname:       vars["host"],
		Port:           vars["port"],
		Expiry:         vars["expiry"],
		CommandEncoded: vars["command"],
		EncryptedMSG:   vars["encrypted_msg"],
		Mac:            vars["mac"],
	}
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("INTERNAL_KEYS_SIGN")))

	// Write Data to it
	h.Write([]byte(p.User + "," + p.Hostname + "," + p.Port + "," + p.Expiry + "," + p.CommandEncoded + "," + p.EncryptedMSG))
	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != p.Mac {
		zap.S().Error("HMAC mismatch")
		return
	}

	priv, err := machine.GetPrivateKey(p.EncryptedMSG, p.Expiry)
	if err != nil {
		zap.S().Error(err)
		return
	}

	config := &ssh.ClientConfig{
		User: p.User,
		Auth: []ssh.AuthMethod{
			priv,
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	connSSH, err := ssh.Dial("tcp", p.Hostname+":"+p.Port, config)
	if err != nil {
		zap.S().Error("Failed to dial: " + err.Error())
		return
	}
	defer connSSH.Close()
	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := connSSH.NewSession()
	if err != nil {
		zap.S().Error("Failed to create session: " + err.Error())
		return
	}
	defer session.Close()

	remoteStdin, err := session.StdinPipe()
	if err != nil {
		zap.S().Error("Failed to create stdinpipe: " + err.Error())
		return
	}
	remoteStdout, err := session.StdoutPipe()
	if err != nil {
		zap.S().Error("Failed to create stdoutpipe: " + err.Error())
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
		zap.S().Errorf("request for pseudo terminal failed: %s\n", err)
		return
	}

	decodedCommand, err := base64.RawURLEncoding.WithPadding('=').DecodeString(p.CommandEncoded)
	if err != nil {
		zap.S().Error(err)
		return
	}

	if string(decodedCommand) == "default" {
		// Start remote shell
		if err := session.Shell(); err != nil {
			zap.S().Errorf("failed to start shell: %s\n", err)
			return
		}

	} else {

		err = session.Start(string(decodedCommand))
		if err != nil {
			zap.S().Errorf("failed to start with command: %s\n", err)
			return
		}

	}

	var wg sync.WaitGroup
	resizer := machine.Terminal{
		Session: session,
	}

	wg.Add(3)
	go sshIO.ForwardClientMessageToHostOrResize(ctx, cancel, conn, &wg, &resizer, remoteStdin)
	go sshIO.ForwardHostMessageToClient(ctx, cancel, conn, &wg, remoteStdout)
	go pingWebsocket(ctx, cancel, conn, &wg)
	wg.Wait()

	fmt.Println("SSH connection finished")
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
		zap.S().Error("HMAC mismatch")
		return
	}

	priv, err := machine.GetPrivateKey(vars["encrypted_msg"], vars["expiry"])
	if err != nil {
		zap.S().Error(err)
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
		zap.S().Error(err)
		return
	}
	defer conn.Close()

	s, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tunnel.Local.Port)), *dialTimeout)
	if err != nil {
		zap.S().Error(err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go sshIO.ForwardClientMessageToHost(ctx, cancel, conn, &wg, s)
	go sshIO.ForwardHostMessageToClient(ctx, cancel, conn, &wg, s)
	go pingWebsocket(ctx, cancel, conn, &wg)

	wg.Wait()
	zap.S().Info("VNC connection finished")
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
				zap.S().Info("ping:", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func main() {
	zap.S().Info("Starting up sheller")
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

	m := mux.NewRouter()
	m.HandleFunc("/stream/{job_id}", handleLogsConsumer)
	m.HandleFunc("/k8s-exec/{pod}/{container}/{cluster}/{expiry}/{encrypted_msg}/{mac}", handleKubernetes)
	m.HandleFunc("/docker-attach/{name}/{cluster}/{machineID}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleDocker)
	m.HandleFunc("/lxd-exec/{name}/{cluster}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleLXD)
	m.HandleFunc("/ssh/{user}/{host}/{port}/{expiry}/{command}/{encrypted_msg}/{mac}", handleSSH)
	m.HandleFunc("/proxy/{proxy}/{host}/{port}/{expiry}/{encrypted_msg}/{mac}", handleVNC)
	m.HandleFunc("/ssh/jobs/{job_id}", func(w http.ResponseWriter, r *http.Request) { handleJob(w, r) })

	s := &http.Server{
		Addr:           *listen,
		Handler:        m,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	zap.S().Fatal(s.ListenAndServe())
}
