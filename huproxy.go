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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	//"github.com/elliotchance/sshtunnel"
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

	upgrader websocket.Upgrader
)

func startSSH(server, user, keyString string, session *ssh.Session) {
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	// Start remote shell
	if err := session.Shell(); err != nil {
		log.Fatalf("failed to start shell: %s", err)
	}
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

func handleProxy(w http.ResponseWriter, r *http.Request) {
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
	sha := hex.EncodeToString(h.Sum(nil))

	if sha != mac {
		log.Println("HMAC mismatch")
		return
	}

	if expiry < time.Now().Unix() {
		log.Println("Session expired")
		return
	}

	mctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(mctx, options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	if err != nil {
		log.Fatal(err)
		return
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")
	collection := client.Database("mist2").Collection("keys")
	//objID, err := primitive.ObjectIDFromHex(keyID)
	//if err != nil {
	//	log.Println(keyID)
	//	log.Fatal(err)
	//}

	key := Key{}

	findResult := collection.FindOne(mctx, bson.M{"_id": keyID})
	if err := findResult.Err(); err != nil {
		log.Println(keyID)
		log.Fatal(err)
	}
	err = findResult.Decode(&key)
	if err != nil {
		log.Fatal(err)
	}

	proxySplit := strings.Split(proxy, "@")
	username := proxySplit[0]
	hostAndPort := proxySplit[1]

	signer, err := ssh.ParsePrivateKey([]byte(key.Private))
	if err != nil {
		panic("Failed to parse private key: " + err.Error())
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	connSSH, err := ssh.Dial("tcp", hostAndPort, config)
	if err != nil {
		panic("Failed to dial: " + err.Error())
	}
	defer connSSH.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := connSSH.NewSession()
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}
	defer session.Close()

	remoteStdin, err := session.StdinPipe()
	if err != nil {
		panic("Failed to create stdinpipe: " + err.Error())
	}
	remoteStdout, err := session.StdoutPipe()
	if err != nil {
		panic("Failed to create stdoutpipe: " + err.Error())
	}

	go startSSH(hostAndPort, username, key.Private, session)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	defer conn.Close()

	// websocket -> server
	go func() {
		for {
			mt, r, err := conn.NextReader()
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
				log.Fatal("blah")
			}

			if _, err := io.Copy(remoteStdin, r); err != nil {
				log.Printf("Reading from websocket: %v", err)
				cancel()
			}
		}
	}()

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
	m.HandleFunc("/proxy/{proxy}/{key}/{expiry}/{mac}", handleProxy)
	s := &http.Server{
		Addr:           *listen,
		Handler:        m,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
