package stream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	sheller "sheller/lib"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/amqp"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/stream"
)

const (
	host     = "rabbitmq"
	port     = 5552
	user     = "guest"
	password = "guest"
)

func CreateStreamProducer(job_id string) (*stream.Producer, error) {
	env, err := stream.NewEnvironment(
		stream.NewEnvironmentOptions().
			SetHost(host).
			SetPort(port).
			SetUser(user).
			SetPassword(password).
			SetMaxConsumersPerClient(20))
	if err != nil {
		return nil, err
	}
	err = env.DeclareStream(job_id,
		&stream.StreamOptions{
			MaxLengthBytes: stream.ByteCapacity{}.MB(300),
		},
	)
	if err != nil {
		return nil, err
	}
	producer, err := env.NewProducer(job_id, nil)
	if err != nil {
		return nil, err
	}
	return producer, nil
}

func HostProducer(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, reader io.Reader, producer *stream.Producer, job_id string) {
	defer wg.Done()
	defer cancel()
	defer func() {
		err := producer.Close()
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
		data := bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
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

func HostProducerWebsocket(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, conn *websocket.Conn, producer *stream.Producer, job_id string) {
	defer wg.Done()
	defer cancel()
	defer func() {
		err := producer.Close()
		if err != nil {
			log.Println(err)
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		reader, err := sheller.GetNextReader(ctx, conn)
		if err != nil {
			log.Println(err)
		}
		b := make([]byte, 32*1024)
		if n, err := reader.Read(b); err == io.EOF {
			log.Println("received EOF from host, closing producer...")
			return
		} else if err != nil {
			log.Println(err)
			return
		} else {
			if b[0] == 1 || b[0] == 2 {
				// b[0]=1 is for kubernetes
				b = b[1:n]
			} else if b[0] != 0 {
				b = b[:n]
			} else {
				continue
			}
		}
		err = producer.Send(amqp.NewMessage(b))
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func JobStreamConsumerWebsocket(job_id string, conn *websocket.Conn) {
	env, err := stream.NewEnvironment(
		stream.NewEnvironmentOptions().
			SetHost(host).
			SetPort(port).
			SetUser(user).
			SetPassword(password))
	if err != nil {
		log.Println(err)
	}
	handleMessages := func(consumerContext stream.ConsumerContext, message *amqp.Message) {
		data := fmt.Sprintf("%s\n", message.Data)

		err := conn.WriteMessage(websocket.BinaryMessage, []byte(strings.ReplaceAll(strings.ReplaceAll(data, "[", ""), "]", "")))
		if err != nil {
			log.Println(err)
			return
		}
	}
	consumer_id := uuid.New().String()

	_, err = env.NewConsumer(job_id,
		handleMessages,
		stream.NewConsumerOptions().
			SetConsumerName(job_id+consumer_id). // set a consumerOffsetNumber name
			SetOffset(stream.OffsetSpecification{}.First()))
	if err != nil {
		log.Println(err)
		return
	}
	/*
		err = consumerNext.Close()
		if err != nil {
			log.Println(err)
			return
		}

			err = env.DeleteStream(job_id)
			if err != nil {
				log.Println(err)
				return
			}
	*/
}
