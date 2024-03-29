package stream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/amqp"
	"github.com/rabbitmq/rabbitmq-stream-go-client/pkg/stream"
	"go.uber.org/zap"
)

const (
	port                  = 5552
	MaxConsumersPerClient = 50
	StreamCapacity        = 200 // MB
)

func init() {
	_, host_exists := os.LookupEnv("RABBITMQ_HOST")
	_, user_exists := os.LookupEnv("RABBITMQ_USERNAME")
	_, password_exists := os.LookupEnv("RABBITMQ_PASSWORD")
	if host_exists && user_exists && password_exists {
		return
	} else {
		zap.S().Error("RabbitMQ environment variables not found")
	}
}

func createEnv() (*stream.Environment, error) {
	env, err := stream.NewEnvironment(
		stream.NewEnvironmentOptions().
			SetHost(os.Getenv("RABBITMQ_HOST")).
			SetPort(port).
			SetUser(os.Getenv("RABBITMQ_USERNAME")).
			SetPassword(os.Getenv("RABBITMQ_PASSWORD")).
			SetMaxConsumersPerClient(MaxConsumersPerClient))
	if err != nil {
		return nil, err
	}
	return env, nil
}

func HostProducer(ctx context.Context, reader io.Reader, jobID string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	// Create stream environment.
	env, err := createEnv()
	if err != nil {
		zap.S().Error(err)
		return
	}

	// Use jobID as the streamName .
	err = env.DeclareStream(jobID,
		&stream.StreamOptions{
			MaxLengthBytes: stream.ByteCapacity{}.MB(StreamCapacity),
		},
	)
	if err != nil {
		zap.S().Error(err)
	}

	// Create a *stream.Producer and use the stream that was
	// declared above.
	producer, err := env.NewProducer(jobID, nil)
	if err != nil {
		zap.S().Error(err)
		return
	}

	// We don't want to keep the stream when the job is done
	// so delete the stream before closing the stream
	// environment.
	defer func() {
		err := producer.Close()
		if err != nil {
			zap.S().Error(err)
			return
		}
		err = env.DeleteStream(jobID)
		if err != nil {
			zap.S().Error(errors.New("delete stream: " + err.Error()))
		}
		err = env.Close()
		if err != nil {
			zap.S().Error(err)
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		b := make([]byte, 32*1024)
		if n, err := reader.Read(b); err == io.EOF {
			zap.S().Error("received EOF from host, closing producer...")
			return
		} else if err != nil {
			zap.S().Error(err)
			return
		} else {
			b = b[:n]
		}
		data := bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
		zap.S().Infof("Sending data: %s", data)
		err = producer.Send(amqp.NewMessage(data))
		if err != nil {
			zap.S().Error(err)
			return
		}
	}
}

func JobStreamConsumerWebsocket(ctx context.Context, cancel context.CancelFunc, jobID string, conn *websocket.Conn, log *log.Logger) {
	defer cancel()
	conn.SetPongHandler(func(string) error { conn.SetReadDeadline(time.Now().Add(15 * time.Second)); return nil })
	env, err := createEnv()
	if err != nil {
		zap.S().Error(err)
		return
	}
	defer env.Close()

	// Handle incoming messages by writing the message to the websocket client.
	handleMessages := func(consumerContext stream.ConsumerContext, message *amqp.Message) {
		data := fmt.Sprintf("%s\n", message.Data)
		err := conn.WriteMessage(websocket.BinaryMessage, []byte(strings.ReplaceAll(strings.ReplaceAll(data, "[", ""), "]", "")))
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Generate a UUID based on RFC 4122.
	consumer_id := uuid.New().String()
	consumerNext, err := env.NewConsumer(jobID,
		handleMessages,
		stream.NewConsumerOptions().
			SetConsumerName(consumer_id).
			SetOffset(stream.OffsetSpecification{}.First()))
	if err != nil {
		zap.S().Error(err)
		return
	}

	// Wait until context is done to close the
	// consumer.
	for {
		select {
		case <-ctx.Done():
			err = consumerNext.Close()
			if err != nil {
				zap.S().Error(err)
			}
			return
		}
	}
}
