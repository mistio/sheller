package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"sheller/machine"
	"sheller/util/cancelable"
	"sheller/util/stream"
	"sheller/util/websocketLog"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
)

type sshRequestPayload struct {
	User           string `json:"user"`
	Hostname       string `json:"hostname"`
	Port           string `json:"port"`
	Expiry         string `json:"expiry"`
	CommandEncoded string `json:"command_encoded"`
	EncryptedMSG   string `json:"encrypted_msg"`
	Mac            string `json:"mac"`
}

type scriptJobs struct {
	mu   sync.Mutex
	data map[string]sshRequestPayload
}

var jobs scriptJobs

func (s *scriptJobs) update(jobId string, data sshRequestPayload) {
	s.mu.Lock()
	s.data[jobId] = data
	s.mu.Unlock()
}

func (s *scriptJobs) readJob(jobId string) sshRequestPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[jobId]
}

func receiveScriptHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	job_id := vars["job_id"]
	decoder := json.NewDecoder(r.Body)
	var p sshRequestPayload
	err := decoder.Decode(&p)
	if err != nil {
		jobs.update(job_id, p)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func runScriptHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	job_id := vars["job_id"]
	p := jobs.readJob(job_id)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Time{})
	WSLogger := websocketLog.WebsocketWriter{
		Conn: conn,
	}
	log := websocketLog.WrapLogger(WSLogger)
	user := p.User
	host := p.Hostname
	port := p.Port
	mac := p.Mac
	command := p.CommandEncoded
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

	decodedCommand, err := base64.RawURLEncoding.WithPadding('=').DecodeString(command)
	if err != nil {
		log.Println(err)
		return
	}

	err = session.Start(string(decodedCommand))
	if err != nil {
		log.Printf("failed to start with command: %s\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go stream.HostProducer(ctx, cancel, conn, &wg, remoteStdout, job_id)
	go pingWebsocket(ctx, cancel, conn, &wg)
	wg.Wait()
}
