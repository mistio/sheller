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
	"time"

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

	upgrader websocket.Upgrader
)

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
	host := vars["host"]
	port := vars["port"]
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	mac := vars["mac"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))

	// Write Data to it
	h.Write([]byte(proxy + "," + keyID + "," + host + "," + port + "," + vars["expiry"]))

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

	priv, err := ssh.ParsePrivateKey([]byte(key.Private))
	if err != nil {
		log.Fatal(err)
	}
	// Setup the tunnel, but do not yet start it yet.
	tunnel := sshtunnel.NewSSHTunnel(
		// User and host of tunnel server, it will default to port 22
		// if not specified.
		proxy,
		ssh.PublicKeys(priv), // 1. private key
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
				return
			}
			if err != nil {
				log.Printf("nextreader: %v", err)
				return
			}
			if mt != websocket.BinaryMessage {
				log.Fatal("blah")
			}
			if _, err := io.Copy(s, r); err != nil {
				log.Printf("Reading from websocket: %v", err)
				cancel()
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
	m.HandleFunc("/proxy/{proxy}/{key}/{host}/{port}/{expiry}/{mac}", handleProxy)
	s := &http.Server{
		Addr:           *listen,
		Handler:        m,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
