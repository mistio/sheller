package stream

import (
	"context"
	"fmt"
	"io"
	"log"
	sheller "sheller/lib"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/amqp"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/stream"
)

func createStreamEnv() (*stream.Environment, error) {
	env, err := stream.NewEnvironment(
		stream.NewEnvironmentOptions().
			SetHost("rabbitmq").
			SetPort(5552).
			SetUser("guest").
			SetPassword("guest"))
	if err != nil {
		log.Println("New")
		return nil, err
	}
	return env, nil
}

func CreateStreamProducer(job_id string) (*stream.Producer, error) {
	env, err := createStreamEnv()
	if err != nil {
		return nil, err
	}
	err = env.DeclareStream(job_id,
		&stream.StreamOptions{
			MaxLengthBytes: stream.ByteCapacity{}.GB(2),
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

func HostProducer(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, reader io.Reader, producer *stream.Producer) {
	defer wg.Done()
	defer cancel()
	defer func() {
		err := producer.Close()
		if err != nil {
			log.Println(err)
		}
	}()
	// for testing purposes
	go jobStreamConsumer()
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
		err := producer.Send(amqp.NewMessage(b))
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func HostProducerWebsocket(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, conn *websocket.Conn, producer *stream.Producer) {
	defer wg.Done()
	defer cancel()
	defer func() {
		err := producer.Close()
		if err != nil {
			log.Println(err)
		}
	}()
	// for testing purposes
	go jobStreamConsumer()
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

func jobStreamConsumer() {
	// add ctx
	job_id := "test"
	env, err := createStreamEnv()
	if err != nil {
		log.Println(err)
		return
	}
	handleMessages := func(consumerContext stream.ConsumerContext, message *amqp.Message) {
		fmt.Printf("%s", message.Data)
		// TODO:
		// write back to a websocket connection that
		// the client will use to read the streaming logs
	}
	_, err = env.NewConsumer(job_id,
		handleMessages,
		stream.NewConsumerOptions().
			SetConsumerName(job_id+"consumer"). // set a consumerOffsetNumber name
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

func JobStreamConsumerWebsocket(job_id string, conn *websocket.Conn) {
	env, err := createStreamEnv()
	if err != nil {
		log.Println(err)
		return
	}
	handleMessages := func(consumerContext stream.ConsumerContext, message *amqp.Message) {
		for _, b := range message.Data {
			err := conn.WriteMessage(websocket.BinaryMessage, b)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
	_, err = env.NewConsumer(job_id,
		handleMessages,
		stream.NewConsumerOptions().
			SetConsumerName(job_id+"consumer"). // set a consumerOffsetNumber name
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
