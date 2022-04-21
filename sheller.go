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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"text/template"

	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	sheller "sheller/lib"

	"github.com/elliotchance/sshtunnel"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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
	kubeconfig string
	upgrader   websocket.Upgrader
)
var kube_config_template string = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {{.Certificate_authority_data}}
    server: {{.Server}}
  name: {{.Cluster}}
contexts:
- context:
    cluster: {{.Cluster}}
    user: {{.User}}
  name: {{.Context_name}}
current-context: {{.Context_name}}
kind: Config
preferences: {}
users:
- name: {{.User}}
  user:
    client-certificate-data: {{.Client_certificate_data}}
    client-key-data: {{.Client_key_data}}
`

type ExecOptions struct {
	Namespace string
	Pod       string
	Container string
	Command   []string
	TTY       bool
	Stdin     bool
}

type KubeConfigTemplate struct {
	Certificate_authority_data string
	Server                     string
	Cluster                    string
	User                       string
	Context_name               string
	Client_certificate_data    string
	Client_key_data            string
}
type WebsocketRoundTripper struct {
	TLSConfig *tls.Config
}

var KubeProtocols = []string{
	"v4.channel.k8s.io",
	"v3.channel.k8s.io",
	"v2.channel.k8s.io",
	"channel.k8s.io",
}

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

func k8s_ExecRequest(config *rest.Config, opts *ExecOptions) (*http.Request, error) {
	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("Unrecognised URL scheme in %v", u)
	}

	u.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec", opts.Namespace, opts.Pod)

	rawQuery := "stdout=true&tty=true"
	for _, c := range opts.Command {
		rawQuery += "&command=" + c
	}

	if opts.Container != "" {
		rawQuery += "&container=" + opts.Container
	}

	if opts.TTY {
		rawQuery += "&tty=true"
	}

	if opts.Stdin {
		rawQuery += "&stdin=true"
	}
	u.RawQuery = rawQuery

	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
	}, nil
}

type DockerExecOptions struct {
	Host       string
	Port       string
	Machine_id string
	Name       string
	Cluster    string
}

func docker_ExecRequest(opts *DockerExecOptions) (*http.Request, error) {
	//create empty url to be populated
	u := &url.URL{}
	u.Scheme = "http"
	u.Host = opts.Host + ":" + opts.Port

	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("Unrecognised URL scheme in %v", u)
	}

	u.Path = fmt.Sprintf("/containers/%s/attach/ws", opts.Machine_id)
	u.RawQuery = "logs=1&stream=0&stdin=1&stdout=1&stderr=1"

	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
	}, nil
}

// Key model
type Key struct {
	ID        string `bson:"_id, omitempty"`
	Class     string `bson:"_cls"`
	Name      string `bson:"name" json:"name"`
	Owner     string `bson:"owner" json:"owner"`
	Default   bool   `bson:"default" json:"default"`
	Public    string `bson:"public" json:"public"`
	OwnedBy   string `bson:"owned_by" json:"owned_by"`
	CreatedBy string `bson:"created_by" json:"created_by"`
}

// Portal model
type Portal struct {
	ID             string `bson:"_id, omitempty"`
	InternalApiKey string `bson:"internal_api_key, omitempty"`
}

type KeyMachineAssociation struct {
	ID       primitive.ObjectID `bson:"_id, omitempty"`
	Class    string             `bson:"_cls"`
	Key      string             `bson:"key" json:"key"`
	LastUsed int                `bson:"last_used" json:"last_used"`
	SSHUser  string             `bson:"ssh_user" json:"ssh_user"`
	Sudo     bool               `bson:"sudo" json:"sudo"`
	Port     int                `bson:"port" json:"port"`
}

type terminalSize struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

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

func getPrivateKey(h hash.Hash, mac string, expiry int64, keyID string, sessionCookie string) (ssh.AuthMethod, error) {
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
	mongoURI := os.Getenv("MONGO_URI")
	if !strings.HasPrefix(mongoURI, "mongodb://") {
		mongoURI = "mongodb://" + mongoURI
	}
	client, err := mongo.Connect(mctx, options.Client().ApplyURI(mongoURI))
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
	log.Println("Fetching API key")
	apikey, err := getApiKey(client)

	internalApiUrl := os.Getenv("INTERNAL_API_URL")
	if len(internalApiUrl) == 0 {
		internalApiUrl = "http://api"
	}
	url := internalApiUrl + "/api/v1/keys/" + key.ID + "/private"

	mistApiClient := http.Client{
		Timeout: time.Second * 20,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Authorization", "internal "+apikey+" "+sessionCookie)

	res, getErr := mistApiClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	keyBody := fmt.Sprintf("%s", body)
	keyBody = strings.Replace(keyBody, `\n`, "\n", -1)
	keyBody = strings.Replace(keyBody, `"`, "", -1)
	priv, err := ssh.ParsePrivateKey([]byte(keyBody))
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(priv), nil
}

func mongoClient() (*mongo.Client, error) {
	mongoURI := os.Getenv("MONGO_URI")
	if !strings.HasPrefix(mongoURI, "mongodb://") {
		mongoURI = "mongodb://" + mongoURI
	}
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		return nil, err
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}
	log.Println("Connected to MongoDB!")

	return client, nil
}

func getKeyMachineAssociation(client *mongo.Client, keyMachineAssociationID string) (*KeyMachineAssociation, error) {
	mctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := client.Database("mist2").Collection("key_association")

	docID, _ := primitive.ObjectIDFromHex(keyMachineAssociationID)
	keyMachineAssociation := &KeyMachineAssociation{}

	findResult := collection.FindOne(mctx, bson.M{"_id": docID})
	if err := findResult.Err(); err != nil {
		return nil, err
	}

	err := findResult.Decode(keyMachineAssociation)
	if err != nil {
		return nil, err
	}
	return keyMachineAssociation, nil
}

func getKey(client *mongo.Client, keyID string) (*Key, error) {
	mctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := client.Database("mist2").Collection("keys")

	key := &Key{}

	findResult := collection.FindOne(mctx, bson.M{"_id": keyID})
	if err := findResult.Err(); err != nil {
		return nil, err
	}
	err := findResult.Decode(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func getApiKey(client *mongo.Client) (string, error) {
	mctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	log.Println(("Getting portal from db"))
	collection := client.Database("mist2").Collection("portal")

	portal := &Portal{}

	findResult := collection.FindOne(mctx, bson.M{})
	if err := findResult.Err(); err != nil {
		return "", err
	}
	log.Println(("Decoding portal"))
	err := findResult.Decode(portal)
	if err != nil {
		return "", err
	}
	return portal.InternalApiKey, nil
}

func saveFailedAttemptKeyMachineAssociation(client *mongo.Client, keyMachineAssociationID string) error {
	mctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	docID, err := primitive.ObjectIDFromHex(keyMachineAssociationID)
	if err != nil {
		return err
	}

	collection := client.Database("mist2").Collection("key_association")

	_, err = collection.UpdateOne(mctx, bson.M{"_id": docID}, bson.M{"$set": bson.M{"last_used": -1}})
	if err != nil {
		return err
	}
	return nil
}

func getPrivateKeyFromKeyMachineAssociation(client *mongo.Client, h hash.Hash, mac string, expiry int64, keyMachineAssociationID string, sessionCookie string) (ssh.AuthMethod, error) {
	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	if sha != mac {
		return nil, errors.New("HMAC mismatch")
	}

	if expiry < time.Now().Unix() {
		return nil, errors.New("Session expired")
	}

	keyMachineAssociation, err := getKeyMachineAssociation(client, keyMachineAssociationID)
	if err != nil {
		return nil, err
	}

	key, err := getKey(client, keyMachineAssociation.Key)
	if err != nil {
		return nil, err
	}
	log.Println("Fetching API key")
	apikey, err := getApiKey(client)

	internalApiUrl := os.Getenv("INTERNAL_API_URL")
	if len(internalApiUrl) == 0 {
		internalApiUrl = "http://api"
	}
	url := internalApiUrl + "/api/v1/keys/" + key.ID + "/private"

	mistApiClient := http.Client{
		Timeout: time.Second * 20,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Authorization", "internal "+apikey+" "+sessionCookie)

	res, getErr := mistApiClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	// keyBody := string(body)
	keyBody := fmt.Sprintf("%s", body)
	keyBody = strings.Replace(keyBody, `\n`, "\n", -1)
	keyBody = strings.Replace(keyBody, `"`, "", -1)
	priv, err := ssh.ParsePrivateKey([]byte(keyBody))
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

func getNextReader(ctx context.Context, conn *websocket.Conn) (io.Reader, error) {
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
		return nil, fmt.Errorf("Non binary message")
	}
	return r, nil
}

func clientToHostSSH(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, writer io.Writer, session *ssh.Session) {
	defer wg.Done()
	defer cancel()
	// websocket -> server
	conn.SetReadDeadline(time.Now().Add(*pongTimeout))
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	for {
		r, err := getNextReader(ctx, conn)
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
			resizeMessage := terminalSize{}
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
		r, err := getNextReader(ctx, conn)
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
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	vault_token := vars["vault_token"]
	vault_secret_engine_path := vars["vault_secret_engine_path"]
	key_name := vars["key_name"]
	vault_addr := os.Getenv("VAULT_ADDR")
	mac := vars["mac"]
	path := fmt.Sprintf("/v1/%s/data/mist/keys/%s", vault_secret_engine_path, key_name)
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))
	// Write Data to it
	h.Write([]byte(user + "," + host + "," + port + "," + vars["expiry"] + "," + vault_token + "," + vault_secret_engine_path + "," + key_name))

	vault := Vault{
		address:    vault_addr,
		secretPath: path,
		token:      vault_token,
	}
	priv, err := GetPrivateKey(vault, h, mac, expiry)
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
	keyID := vars["key"]
	host := vars["host"]
	port := vars["port"]
	expiry, _ := strconv.ParseInt(vars["expiry"], 10, 64)
	mac := vars["mac"]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(os.Getenv("SECRET")))

	// Write Data to it
	h.Write([]byte(proxy + "," + keyID + "," + host + "," + port + "," + vars["expiry"]))

	sessionCookie, err := r.Cookie("session.id")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(sessionCookie.Value)
	}

	// Get result and encode as hexadecimal string
	priv, err := getPrivateKey(h, mac, expiry, keyID, sessionCookie.Value)
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

	var wg sync.WaitGroup
	wg.Add(3)

	go clientToHost(ctx, cancel, conn, &wg, s)
	go hostToClient(ctx, cancel, conn, &wg, s)
	go pingWebsocket(ctx, cancel, conn, &wg)

	wg.Wait()
	log.Println("VNC connection finished")
}
func parseKubeConfig() {
	/*
		if home := homedir.HomeDir(); home != "" {
			flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			flag.StringVar(&kubeconfig, "kubeconfig", "~/.kube/config", "absolute path to the kubeconfig file")
		}
	*/

	flag.StringVar(&kubeconfig, "kubeconfig", "config", "absolute path to the kubeconfig file")

	flag.Parse()

}

func checkifPodExists(client *kubernetes.Clientset, opts *ExecOptions) error {
	pod, err := client.CoreV1().Pods(opts.Namespace).Get(context.TODO(), opts.Pod, metav1.GetOptions{})
	if pod.Status.Phase == "Running" {
		return nil
	}
	return err
}
func hostToClientContainer(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, podConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	for {
		r, err := getNextReader(ctx, podConn)
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

func clientToHostContainer(ctx context.Context, cancel context.CancelFunc, clientConn *websocket.Conn, podConn *websocket.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()
	clientConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	clientConn.SetPongHandler(func(string) error { clientConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	podConn.SetReadDeadline(time.Now().Add(*pongTimeout))
	podConn.SetPongHandler(func(string) error { podConn.SetReadDeadline(time.Now().Add(*pongTimeout)); return nil })
	log.Print("it go brrrr")
	for {
		r, err := getNextReader(ctx, clientConn)
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
			err := podConn.WriteMessage(websocket.BinaryMessage, cacheBuff.Bytes())
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

func KubeSetup(vars map[string]string) (*websocket.Conn, *http.Response, error) {
	name := vars["name"]
	opts := &ExecOptions{
		Namespace: "default",
		Pod:       name,
		Container: name,
		Command:   []string{"/bin/bash"},
		Stdin:     true,
		TTY:       true,
	}
	base_address := "http://192.168.1.14:8200"
	kubernetesSecretsURI := fmt.Sprintf("/v1/%s/data/mist/clouds/%s", vars["vault_secret_engine_path"], vars["cluster"])
	vault := Vault{
		address:    base_address,
		secretPath: kubernetesSecretsURI,
		token:      vars["vault_token"],
	}
	KubernetesConfigCredentials, err := GetKubernetesConfigCredentials(vault)
	if err != nil {
		return nil, nil, err
	}
	// read file from templates directory
	configTemplate := KubeConfigTemplate{
		Certificate_authority_data: KubernetesConfigCredentials.Ca_cert_file,
		Server:                     "https://" + KubernetesConfigCredentials.Host + ":" + KubernetesConfigCredentials.Port,
		User:                       vars["user"],
		Cluster:                    "kubernetes",
		Context_name:               vars["user"] + "@" + "kubernetes",
		Client_certificate_data:    KubernetesConfigCredentials.Cert_file,
		Client_key_data:            KubernetesConfigCredentials.Key_file,
	}
	configFile, err := os.Create("kubeconfig.txt")
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	defer configFile.Close()
	var temp *template.Template
	// read kube_config string
	temp, err = template.New("").Parse(kube_config_template)
	err = temp.Execute(configFile, configTemplate)
	if err != nil {
		log.Fatalln(err)
	}
	log.Print("kubeconfig.txt created")
	parseKubeConfig()
	config, err := clientcmd.BuildConfigFromFlags("", "kubeconfig.txt")
	if err != nil {
		log.Fatalln(err)
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	err = checkifPodExists(clientSet, opts)
	if err != nil {
		panic(err.Error())
	}
	req, err := k8s_ExecRequest(config, opts)
	if err != nil {
		log.Fatalln(err)
	}
	// create an http post request

	tlsConfig, err := rest.TLSConfigFor(config)
	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
		Subprotocols:    KubeProtocols,
	}
	podConn, Response, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		log.Println(err)
	}
	return podConn, Response, err
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
	podConn, _, err := KubeSetup(vars)
	defer podConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	go hostToClientContainer(ctx, cancel, clientConn, podConn, &wg)
	go clientToHostContainer(ctx, cancel, clientConn, podConn, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, podConn, &wg)
	wg.Wait()
}
func handleDocker(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Print(vars)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Print(err)
	}
	cacheBuff.Write([]byte{0})
	base_address := "http://192.168.1.14:8200"
	dockerSecretsURI := fmt.Sprintf("/v1/%s/data/mist/clouds/%s", vars["vault_secret_engine_path"], vars["cluster"])
	vault := Vault{
		address:    base_address,
		secretPath: dockerSecretsURI,
		token:      vars["vault_token"],
	}
	DockerConfigCredentials, err := GetDockerConfigCredentials(vault)
	opts := &DockerExecOptions{
		Host:       DockerConfigCredentials.Host,
		Port:       DockerConfigCredentials.Port,
		Machine_id: vars["machine_id"],
		Name:       vars["name"],
		Cluster:    vars["cluster"],
	}
	cert, err := tls.X509KeyPair([]byte(DockerConfigCredentials.Cert_file), []byte(DockerConfigCredentials.Key_file))
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(DockerConfigCredentials.Ca_cert_file))
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}
	dialer := &websocket.Dialer{
		TLSClientConfig: cfg,
	}
	req, err := docker_ExecRequest(opts)
	// DOESN'T WORK
	podConn, d, err := dialer.Dial(req.URL.String(), req.Header)
	if err != nil {
		log.Fatalln(err)
	}
	log.Print(d.Body)
	defer podConn.Close()
	wg := sync.WaitGroup{}
	wg.Add(4)
	go hostToClientContainer(ctx, cancel, clientConn, podConn, &wg)
	go clientToHostContainer(ctx, cancel, clientConn, podConn, &wg)
	go pingWebsocket(ctx, cancel, clientConn, &wg)
	go pingWebsocket(ctx, cancel, podConn, &wg)
	wg.Wait()
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
	m.HandleFunc("/k8s-exec/{name}/{cluster}/{user}/{vault_token}/{vault_secret_engine_path}/{key_name}", handleKubernetes)
	m.HandleFunc("/docker-exec/{host}/{port}/{machine_id}/{name}/{cluster}/{user}/{vault_token}/{vault_secret_engine_path}/{key_name}", handleDocker)
	m.HandleFunc("/ssh/{user}/{host}/{port}/{expiry}/{vault_token}/{vault_secret_engine_path}/{key_name}/{mac}", handleSSH)
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
