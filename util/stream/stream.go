package stream

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/amqp"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/stream"
)

var writeTimeout = flag.Duration("write_timeout", 10*time.Second, "Write timeout.")

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

func hostToClientProducer(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, wg *sync.WaitGroup, reader io.Reader, producer *stream.Producer) {
	defer wg.Done()
	defer cancel()
	defer func() {
		err := producer.Close()
		if err != nil {
			log.Println(err)
		}
	}()
	go jobStreamConsumer()
	for {
		if ctx.Err() != nil {
			return
		}
		b := make([]byte, 32*1024)
		if n, err := reader.Read(b); err == io.EOF {
			if err := conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(*writeTimeout)); err == websocket.ErrCloseSent {
			} else if err != nil {
				log.Printf("Error sending close message: %v", err)
			}
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

func jobStreamConsumer() {
	// add ctx
	job_id := "test"
	env, err := createStreamEnv()
	if err != nil {
		log.Println(err)
		return
	}
	var counter int32
	handleMessages := func(consumerContext stream.ConsumerContext, message *amqp.Message) {
		fmt.Printf("messages consumed: %d \n ", atomic.AddInt32(&counter, 1))
		fmt.Printf("%s", message.Data)
		// TODO:
		// write back to a websocket connection that
		// the client will use to read the streaming logs
	}
	atomic.StoreInt32(&counter, 0)
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
