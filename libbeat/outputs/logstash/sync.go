package logstash

import (
	"errors"
	"expvar"
	"net"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

// Metrics that can retrieved through the expvar web interface.
var (
	ackedEvents            = expvar.NewInt("libbeatLogstashPublishedAndAckedEvents")
	eventsNotAcked         = expvar.NewInt("libbeatLogstashPublishedButNotAckedEvents")
	publishEventsCallCount = expvar.NewInt("libbeatLogstashPublishEventsCallCount")
)

// client implements the ProtocolClient interface to be used
// with different mode. The client implements slow start with low window sizes +
// window size backoff in case of long running transactions.
//
// it is suggested to use lumberjack in conjunction with roundRobinConnectionMode
// if logstash becomes unresponsive
type client struct {
	TransportClient
	*protocol

	win             window
	countTimeoutErr int
}

const (
	minWindowSize             int = 1
	defaultStartMaxWindowSize int = 10
	maxAllowedTimeoutErr      int = 3
)

// errors
var (
	ErrNotConnected = errors.New("lumberjack client is not connected")
)

func newLumberjackClient(
	conn TransportClient,
	compressLevel int,
	maxWindowSize int,
	timeout time.Duration,
) (*client, error) {
	p, err := newClientProcol(conn, timeout, compressLevel)
	if err != nil {
		return nil, err
	}

	c := &client{
		TransportClient: conn,
		protocol:        p,
	}
	c.win.init(defaultStartMaxWindowSize, maxWindowSize)
	return c, nil
}

func (l *client) Connect(timeout time.Duration) error {
	logp.Debug("logstash", "connect")
	return l.TransportClient.Connect(timeout)
}

func (l *client) Close() error {
	logp.Debug("logstash", "close connection")
	return l.TransportClient.Close()
}

func (l *client) PublishEvent(event common.MapStr) error {
	_, err := l.PublishEvents([]common.MapStr{event})
	return err
}

// PublishEvents sends all events to logstash. On error a slice with all events
// not published or confirmed to be processed by logstash will be returned.
func (l *client) PublishEvents(
	events []common.MapStr,
) ([]common.MapStr, error) {
	publishEventsCallCount.Add(1)
	totalNumberOfEvents := len(events)
	for len(events) > 0 {
		n, err := l.publishWindowed(events)

		logp.Debug("logstash", "%v events out of %v events sent to logstash. Continue sending ...", n, len(events))
		events = events[n:]
		if err != nil {
			logp.Err("Failed to publish events caused by: %v", err)

			eventsNotAcked.Add(int64(len(events)))
			ackedEvents.Add(int64(totalNumberOfEvents - len(events)))
			return events, err
		}
	}
	ackedEvents.Add(int64(totalNumberOfEvents))
	return nil, nil
}

// publishWindowed published events with current maximum window size to logstash
// returning the total number of events sent (due to window size, or acks until
// failure).
func (l *client) publishWindowed(events []common.MapStr) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}

	batchSize := len(events)
	windowSize := l.win.get()
	debug("Try to publish %v events to logstash with window size %v",
		batchSize, windowSize)

	// prepare message payload
	if batchSize > windowSize {
		events = events[:windowSize]
	}

	outEvents, err := l.sendEvents(events)
	count := uint32(len(outEvents))
	if err != nil {
		if err == errAllEventsEncoding {
			return len(events), nil
		}
		return l.onFail(0, err)
	}

	if seq, err := l.awaitACK(count); err != nil {
		return l.onFail(int(seq), err)
	}

	l.win.tryGrowWindow(batchSize)
	return len(events), nil
}

func (l *client) onFail(n int, err error) (int, error) {
	debug("handle error: %v", err)
	l.win.shrinkWindow()

	// if timeout error, back off and ignore error
	nerr, ok := err.(net.Error)
	if !ok || !nerr.Timeout() {
		// no timeout error, close connection and return error
		debug("no timeout error: %v", err)
		_ = l.Close()
		return n, err
	}

	// if we've seen 3 consecutive timeout errors, close connection
	l.countTimeoutErr++
	if l.countTimeoutErr == maxAllowedTimeoutErr {
		l.countTimeoutErr = 0
		_ = l.Close()
		debug("max timeout errors reached, close connection")
		return n, err
	}

	// timeout error. events. Send
	// mode might try to publish again with reduce window size or ask another
	// client to send events
	debug("timeout error, keep connection alive for retrying")
	return n, err
}
