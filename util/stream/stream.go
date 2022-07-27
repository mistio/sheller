package stream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/amqp"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/stream"
)

const (
	host                  = "rabbitmq"
	port                  = 5552
	user                  = "guest"
	password              = "guest"
	MaxConsumersPerClient = 50
	StreamCapacity        = 200 // MB
)

func createEnv() (*stream.Environment, error) {
	env, err := stream.NewEnvironment(
		stream.NewEnvironmentOptions().
			SetHost(host).
			SetPort(port).
			SetUser(user).
			SetPassword(password).
			SetMaxConsumersPerClient(MaxConsumersPerClient))
	if err != nil {
		return nil, err
	}
	return env, nil
}

func HostProducer(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, reader io.Reader, job_id string) {
	defer wg.Done()
	defer cancel()
	env, err := createEnv()
	if err != nil {
		log.Println(err)
		return
	}
	err = env.DeclareStream(job_id,
		&stream.StreamOptions{
			MaxLengthBytes: stream.ByteCapacity{}.MB(StreamCapacity),
		},
	)
	if err != nil {
		log.Println(err)
	}
	producer, err := env.NewProducer(job_id, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		err := producer.Close()
		if err != nil {
			log.Println(err)
			return
		}
		err = env.DeleteStream(job_id)
		if err != nil {
			log.Println(errors.New("delete stream: " + err.Error()))
		}
		err = env.Close()
		if err != nil {
			log.Println(err)
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		b := make([]byte, 32*1024)
		if n, err := reader.Read(b); err == io.EOF {
			log.Println("received EOF from host, closing producer...")
			return
		} else if err != nil {
			log.Println(err)
			return
		} else {
			b = b[:n]
		}
		data := bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
		err := conn.WriteMessage(websocket.BinaryMessage, data)
		if err != nil {
			log.Printf("sending return_code to client: %v\n", err)
		}
		err = producer.Send(amqp.NewMessage(data))
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func JobStreamConsumerWebsocket(ctx context.Context, cancel context.CancelFunc, job_id string, conn *websocket.Conn) {
	defer cancel()
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(0)); return nil })
	env, err := createEnv()
	if err != nil {
		log.Println(err)
		return
	}
	defer env.Close()
	handleMessages := func(consumerContext stream.ConsumerContext, message *amqp.Message) {
		data := fmt.Sprintf("%s\n", message.Data)

		err := conn.WriteMessage(websocket.BinaryMessage, []byte(strings.ReplaceAll(strings.ReplaceAll(data, "[", ""), "]", "")))
		if err != nil {
			log.Println(err)
			return
		}
	}
	consumer_id := uuid.New().String()
	consumerNext, err := env.NewConsumer(job_id,
		handleMessages,
		stream.NewConsumerOptions().
			SetConsumerName(job_id+consumer_id). // set a consumerOffsetNumber name
			SetOffset(stream.OffsetSpecification{}.First()))
	if err != nil {
		log.Println(err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			err = consumerNext.Close()
			if err != nil {
				log.Println(err)
			}
			return
		}
	}
}
