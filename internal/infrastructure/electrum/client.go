// Package electrum watches the chain over the Electrum protocol: newline-delimited JSON-RPC over
// TCP or TLS.
package electrum

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arkade-os/executor/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

const (
	protocolVersion = "1.4"
	clientName      = "executord"
	maxBackoff      = 30 * time.Second
)

// timings are the client's clocks; tests shorten them.
type timings struct {
	request time.Duration // longest wait for an answer
	ping    time.Duration // idle servers drop clients after about ten minutes
	backoff time.Duration // first wait before a reconnect, doubling to maxBackoff
}

var defaultTimings = timings{request: 30 * time.Second, ping: time.Minute, backoff: time.Second}

type call struct {
	method string
	params []any
}

type request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type message struct {
	ID     *uint64         `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// client keeps one connection to the server, matches answers to requests and queues notifications.
// After a drop it dials again and runs onReconnect on the new connection.
type client struct {
	dial        func(ctx context.Context) (net.Conn, error)
	times       timings
	onNotify    func(method string, params json.RawMessage)
	onReconnect func(ctx context.Context) error
	nextID      atomic.Uint64
	notes       notifications
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup

	mu  sync.RWMutex
	cur *session
}

// session is one connection: its writer lock, the requests waiting for an answer and its end.
type session struct {
	conn      net.Conn
	wmu       sync.Mutex
	mu        sync.Mutex
	pending   map[uint64]chan message
	closed    chan struct{}
	closeOnce sync.Once
}

type notification struct {
	method string
	params json.RawMessage
}

// notifications is an unbounded queue: the reader never waits on a consumer that waits on the
// reader.
type notifications struct {
	mu    sync.Mutex
	items []notification
	wake  chan struct{}
}

func (e *rpcError) Error() string { return fmt.Sprintf("electrum: %s (code %d)", e.Message, e.Code) }

func (c *client) start() {
	c.wg.Add(2)
	go c.dispatch()
	go c.keep()
}

func (c *client) close() {
	c.cancel()
	if s := c.session(); s != nil {
		s.close()
	}
	c.wg.Wait()
}

func (c *client) reset() {
	if s := c.session(); s != nil {
		s.close()
	}
}

func (c *client) connected() bool {
	s := c.session()
	if s == nil {
		return false
	}
	select {
	case <-s.closed:
		return false
	default:
		return true
	}
}

func (c *client) session() *session {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cur
}

func (c *client) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	s := c.session()
	if s == nil {
		return nil, ports.ErrDisconnected
	}
	out, err := s.roundTrip(ctx, c, []call{{method, params}}, false)
	if err != nil {
		return nil, err
	}
	return out[0], nil
}

// batch sends the calls as one JSON-RPC batch and returns their results in order.
func (c *client) batch(ctx context.Context, calls []call) ([]json.RawMessage, error) {
	s := c.session()
	if s == nil {
		return nil, ports.ErrDisconnected
	}
	return s.roundTrip(ctx, c, calls, true)
}

func (c *client) connect() error {
	ctx, cancel := context.WithTimeout(c.ctx, c.times.request)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	s := &session{conn: conn, pending: map[uint64]chan message{}, closed: make(chan struct{})}
	c.mu.Lock()
	c.cur = s
	c.mu.Unlock()
	c.wg.Add(2)
	go s.read(c)
	go s.keepAlive(c)
	if _, err := c.call(ctx, "server.version", clientName, protocolVersion); err != nil {
		s.close()
		return err
	}
	return nil
}

// keep dials again whenever the connection ends, waiting longer after each failure.
func (c *client) keep() {
	defer c.wg.Done()
	backoff := c.times.backoff
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.session().closed:
		}
		for {
			if err := c.reconnect(); err == nil {
				backoff = c.times.backoff
				break
			} else if c.ctx.Err() == nil {
				log.WithError(err).Warn("electrum reconnect")
			}
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
		}
	}
}

func (c *client) reconnect() error {
	if err := c.connect(); err != nil {
		return err
	}
	if c.onReconnect == nil {
		return nil
	}
	if err := c.onReconnect(c.ctx); err != nil {
		c.reset()
		return err
	}
	return nil
}

// dispatch hands notifications to onNotify in order, apart from the reader so that it can make
// requests.
func (c *client) dispatch() {
	defer c.wg.Done()
	for {
		n, ok := c.notes.pop(c.ctx)
		if !ok {
			return
		}
		c.onNotify(n.method, n.params)
	}
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
}

func (s *session) roundTrip(
	ctx context.Context, c *client, calls []call, batch bool,
) ([]json.RawMessage, error) {
	select {
	case <-s.closed:
		return nil, ports.ErrDisconnected
	default:
	}
	ctx, cancel := context.WithTimeout(ctx, c.times.request)
	defer cancel()
	reqs := make([]request, len(calls))
	waits := make([]chan message, len(calls))
	s.mu.Lock()
	for i, cl := range calls {
		id := c.nextID.Add(1)
		reqs[i] = request{JSONRPC: "2.0", ID: id, Method: cl.method, Params: cl.params}
		if reqs[i].Params == nil {
			reqs[i].Params = []any{}
		}
		waits[i] = make(chan message, 1)
		s.pending[id] = waits[i]
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		for _, r := range reqs {
			delete(s.pending, r.ID)
		}
		s.mu.Unlock()
	}()
	var payload any = reqs
	if !batch {
		payload = reqs[0]
	}
	if err := s.write(payload); err != nil {
		s.close()
		return nil, ports.ErrDisconnected
	}
	out := make([]json.RawMessage, len(calls))
	for i, wait := range waits {
		select {
		case m := <-wait:
			if m.Error != nil {
				return nil, fmt.Errorf("%s: %w", calls[i].method, m.Error)
			}
			out[i] = m.Result
		case <-s.closed:
			return nil, ports.ErrDisconnected
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return out, nil
}

func (s *session) write(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err = s.conn.Write(append(raw, '\n'))
	return err
}

// read routes each line to the request it answers or to the notification queue, until the
// connection ends.
func (s *session) read(c *client) {
	defer c.wg.Done()
	defer s.close()
	r := bufio.NewReader(s.conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var msgs []message
		if line[0] == '[' {
			err = json.Unmarshal(line, &msgs)
		} else {
			var m message
			err = json.Unmarshal(line, &m)
			msgs = []message{m}
		}
		if err != nil {
			log.WithError(err).Warn("electrum message")
			continue
		}
		for _, m := range msgs {
			s.route(c, m)
		}
	}
}

func (s *session) route(c *client, m message) {
	if m.ID == nil {
		c.notes.push(notification{method: m.Method, params: m.Params})
		return
	}
	s.mu.Lock()
	wait := s.pending[*m.ID]
	s.mu.Unlock()
	if wait != nil {
		wait <- m
	}
}

// keepAlive pings so that an idle server does not drop us, and drops a connection that stops
// answering.
func (s *session) keepAlive(c *client) {
	defer c.wg.Done()
	t := time.NewTicker(c.times.ping)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			if _, err := s.roundTrip(c.ctx, c, []call{{method: "server.ping"}}, false); err != nil {
				log.WithError(err).Warn("electrum ping")
				s.close()
				return
			}
		}
	}
}

func (q *notifications) push(n notification) {
	q.mu.Lock()
	q.items = append(q.items, n)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *notifications) pop(ctx context.Context) (notification, bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			n := q.items[0]
			q.items = q.items[1:]
			q.mu.Unlock()
			return n, true
		}
		q.mu.Unlock()
		select {
		case <-q.wake:
		case <-ctx.Done():
			return notification{}, false
		}
	}
}

// newClient dials the server; start runs it once the hooks are set.
func newClient(rawURL string, times timings) (*client, error) {
	dial, err := dialer(rawURL)
	if err != nil {
		return nil, err
	}
	c := &client{dial: dial, times: times, notes: notifications{wake: make(chan struct{}, 1)}}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if err := c.connect(); err != nil {
		c.cancel()
		return nil, err
	}
	return c, nil
}

// dialer returns how to reach rawURL: tcp:// plain, ssl:// and tls:// encrypted.
func dialer(rawURL string) (func(context.Context) (net.Conn, error), error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("electrum url %q: want tcp://host:port or ssl://host:port", rawURL)
	}
	switch u.Scheme {
	case "tcp":
		return func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", u.Host)
		}, nil
	case "ssl", "tls":
		return func(ctx context.Context) (net.Conn, error) {
			return (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12}}).DialContext(
				ctx, "tcp", u.Host,
			)
		}, nil
	}
	return nil, errors.New("electrum url scheme must be tcp, ssl or tls")
}
