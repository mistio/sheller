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
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"sync"
	"hash"
	"errors"
	"fmt"

	"github.com/elliotchance/sshtunnel"
	huproxy "github.com/google/huproxy/lib"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

	upgrader websocket.Upgrader
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

func NewCancelableReader(ctx context.Context, r io.Reader) *CancelableReader {
	c := &CancelableReader{
		r:    r,
		ctx:  ctx,
		data: make(chan []byte),
	}
	go c.begin()
	return c
}

func getPrivateKey(h hash.Hash, mac string, expiry int64, keyID string) (ssh.AuthMethod, error) {
	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	if sha != mac {
		return nil, errors.New("HMAC mismatch")
	}

	if expiry < time.Now().Unix() {
		return nil, errors.New("Session expired")
	}

	mctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(mctx, options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	if err != nil {
		return nil, err
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)

	if err != nil {
		return nil, err
	}

	log.Println("Connected to MongoDB!")
	collection := client.Database("mist2").Collection("keys")

	key := Key{}

	findResult := collection.FindOne(mctx, bson.M{"_id": keyID})
	if err := findResult.Err(); err != nil {
		return nil, err
	}
	err = findResult.Decode(&key)
	if err != nil {
		return nil, err
	}

	priv, err := ssh.ParsePrivateKey([]byte(key.Private))
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(priv), nil
}

func startSSH(session *ssh.Session) error {
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return fmt.Errorf("request for pseudo terminal failed: %s", err)
	}

	// Start remote shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %s", err)
	}

	return nil
}

// Key model
type Key struct {
	ID        string `bson:"_id, omitempty"`
	Class     string `bson:"_cls"`
	Name      string `bson:"name" json:"name"`
	Owner     string `bson:"owner" json:"owner"`
	Default   bool   `bson:"default" json:"default"`
	Public    string `bson:"public" json:"public"`
	Private   string `bson:"private" json:"private"`
	OwnedBy   string `bson:"owned_by" json:"owned_by"`
	CreatedBy string `bson:"created_by" json:"created_by"`
}

func handleSSH(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	vars := mux.Vars(r)
	proxy := vars["proxy"]
	keyID := vars["key"]
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	mac := vars["mac"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))

	// Write Data to it
	h.Write([]byte(proxy + "," + keyID + "," + vars["expiry"]))

	// Get result and encode as hexadecimal string
	priv, err := getPrivateKey(h, mac, expiry, keyID)
	if err != nil {
		log.Println(err)
		return
	}

	proxySplit := strings.Split(proxy, "@")
	username := proxySplit[0]
	hostAndPort := proxySplit[1]

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			priv,
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	connSSH, err := ssh.Dial("tcp", hostAndPort, config)
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
	remoteStdout = NewCancelableReader(ctx, remoteStdout)

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

	// websocket -> server
	go func() {
		defer wg.Done()
		defer cancel()
		conn.SetReadDeadline(time.Now().Add(*pongTimeout))
		conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
		for {
			mt, r, err := conn.NextReader()
			if ctx.Err() != nil {
				return
			}
			if websocket.IsCloseError(err,
				websocket.CloseNormalClosure,   // Normal.
				websocket.CloseAbnormalClosure, // OpenSSH killed proxy client.
			) {
				return
			}
			if err != nil {
				log.Printf("nextreader: %v", err)
				return
			}
			if mt != websocket.BinaryMessage {
				log.Println("Non binary message")
				return
			}

			if _, err := io.Copy(remoteStdin, r); err != nil {
				log.Printf("Reading from websocket: %v", err)
				return
			}
		}
	}()

	go func() {
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
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		// server -> websocket
		// TODO: NextWriter() seems to be broken.
		if err := huproxy.File2WS(ctx, cancel, remoteStdout, conn); err == io.EOF {
			if err := conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(*writeTimeout)); err == websocket.ErrCloseSent {
			} else if err != nil {
				log.Printf("Error sending close message: %v", err)
			}
		} else if err != nil {
			log.Printf("Reading from file: %v", err)
		}
	}()

	wg.Wait()
	log.Println("SSH connection finished")
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

	priv, err := getPrivateKey(h, mac, expiry, keyID)
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

	// websocket -> server
	go func() {
		for {
			mt, r, err := conn.NextReader()
			if websocket.IsCloseError(err,
				websocket.CloseNormalClosure,   // Normal.
				websocket.CloseAbnormalClosure, // OpenSSH killed proxy client.
			) {
				cancel()
				return
			}
			if err != nil {
				log.Printf("nextreader: %v", err)
				cancel()
				return
			}
			if mt != websocket.BinaryMessage {
				log.Printf("Non binary message")
				cancel()
				return
			}
			if _, err := io.Copy(s, r); err != nil {
				log.Printf("Reading from websocket: %v", err)
				cancel()
				return
			}
		}
	}()

	// server -> websocket
	// TODO: NextWriter() seems to be broken.
	if err := huproxy.File2WS(ctx, cancel, s, conn); err == io.EOF {
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

	log.Printf("huproxy %s", huproxy.Version)
	m := mux.NewRouter()
	m.HandleFunc("/proxy/{proxy}/{key}/{expiry}/{mac}", handleSSH)
	m.HandleFunc("/proxy/{proxy}/{key}/{host}/{port}/{expiry}/{mac}", handleVNC)
	s := &http.Server{
		Addr:           *listen,
		Handler:        m,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
