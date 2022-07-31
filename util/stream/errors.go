package stream

const packageName = "stream"

var (
	ErrCreateStreamEnvironment = packageName + ": failed connecting to a RabbitMQ Stream node"
	ErrDeclareStream           = packageName + ": failed declaring RabbitMQ Stream associated with job_id"
	ErrCreateProducer          = packageName + ": failed creating RabbitMQ Stream producer"
	ErrCloseProducer           = packageName + ": failed closing RabbitMQ Stream producer"
	ErrDeleteStream            = packageName + ": failed deleting RabbitMQ Stream"
	ErrCloseStreamEnvironment  = packageName + ": failed closing connection with RabbitMQ Stream node"
	ErrWriteMessageToAPI       = packageName + ": failed writing command output to mist API"
	ErrReadRemoteStdout        = packageName + ": failed reading from pipe that is connected to the standard output of the remote host"
	ErrProducerSendMessage     = packageName + ": failed sending message to RabbitMQ Stream"
	ErrWriteMessageToClient    = packageName + ": failed writing websocket message from the RabbitMQ Stream to client"
	ErrCreateConsumer          = packageName + ": failed creating consumer that is used to read the requested RabbitMQ Stream associated with job_id"
	ErrCloseConsumer           = packageName + ": failed closing consumer that is used to read the requested RabbitMQ Stream associated with job_id"
)
