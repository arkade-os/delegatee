package electrum

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

var fast = timings{request: 2 * time.Second, ping: time.Hour, backoff: 10 * time.Millisecond}

func TestScriptHashReversesSha256(t *testing.T) {
	hash, err := scriptHash("5120" + strings.Repeat("11", 32))
	require.NoError(t, err)
	require.Equal(t, "994a2bf6fea18f26cf5a88124cfb2d9f993b3717641b9be3b5c2a963a987c9e8", hash)
	_, err = scriptHash("zz")
	require.Error(t, err)
}

func TestRepliesAreMatchedByID(t *testing.T) {
	srv := newServer(t, func(method string, params []any) (any, *rpcError) {
		if params[0] == scriptHashOf(t, "aa") {
			time.Sleep(100 * time.Millisecond)
		}
		return []map[string]any{{"tx_hash": strings.Repeat("ab", 32), "tx_pos": 1, "height": 0, "value": len(params[0].(string))}}, nil
	})
	w := newTestWatcher(t, srv)
	var wg sync.WaitGroup
	got := make([][]ports.Output, 2)
	for i, script := range []string{"aa", "bb"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			got[i], err = w.Unspents(t.Context(), script)
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	for i, script := range []string{"aa", "bb"} {
		require.Equal(t, []ports.Output{{Outpoint: strings.Repeat("ab", 32) + ":1", Script: script, Amount: 64}}, got[i])
	}
}

func TestUnspentsKeepHeightsAndMempool(t *testing.T) {
	srv := newServer(t, func(string, []any) (any, *rpcError) {
		return []map[string]any{
			{"tx_hash": "t1", "tx_pos": 0, "height": 120, "value": 5},
			{"tx_hash": "t2", "tx_pos": 3, "height": 0, "value": 6},
			{"tx_hash": "t3", "tx_pos": 0, "height": -1, "value": 7},
		}, nil
	})
	w := newTestWatcher(t, srv)
	utxos, err := w.Unspents(t.Context(), "aa")
	require.NoError(t, err)
	require.Equal(t, []ports.Output{
		{Outpoint: "t1:0", Script: "aa", Amount: 5, Height: 120},
		{Outpoint: "t2:3", Script: "aa", Amount: 6},
		{Outpoint: "t3:0", Script: "aa", Amount: 7},
	}, utxos)
	_, err = w.Unspents(t.Context(), "zz")
	require.Error(t, err)
}

func TestSubscribePushesTipThenStatuses(t *testing.T) {
	srv := newChain(t, 100)
	srv.status = map[string]any{scriptHashOf(t, "aa"): "s-aa", scriptHashOf(t, "bb"): nil}
	w := newTestWatcher(t, srv)
	sub, err := w.Subscribe(t.Context(), []string{"aa", "bb"})
	require.NoError(t, err)
	defer sub.Stop()

	tip := next(t, sub).Tip
	require.NotNil(t, tip)
	require.Equal(t, int64(100), tip.Height)
	require.Equal(t, time.Unix(1_700_001_000, 0), tip.Time)
	require.Equal(t, time.Unix(1_700_000_950, 0), tip.MedianTime, "the sixth of the last eleven blocks")
	statuses := map[string]string{}
	for range 2 {
		ev := next(t, sub)
		statuses[ev.Script] = ev.Status
	}
	require.Equal(t, map[string]string{"aa": "s-aa", "bb": ""}, statuses)

	_, err = w.Subscribe(t.Context(), nil)
	require.ErrorIs(t, err, errSubscribed)
}

func TestNotificationsReachTheSubscription(t *testing.T) {
	srv := newChain(t, 100)
	w := newTestWatcher(t, srv)
	sub, err := w.Subscribe(t.Context(), []string{"aa"})
	require.NoError(t, err)
	defer sub.Stop()
	for range 2 {
		next(t, sub)
	}

	srv.height = 101
	srv.push("blockchain.headers.subscribe", map[string]any{"height": 101, "hex": ""})
	require.Equal(t, int64(101), next(t, sub).Tip.Height)
	srv.push("blockchain.scripthash.subscribe", scriptHashOf(t, "aa"), "s2")
	require.Equal(t, ports.ChainEvent{Script: "aa", Status: "s2"}, next(t, sub))
	srv.push("blockchain.scripthash.subscribe", scriptHashOf(t, "other"), "s3")
	srv.push("blockchain.unknown", 1)
	srv.push("blockchain.headers.subscribe", "garbage")
	srv.push("blockchain.scripthash.subscribe", "garbage")
	srv.push("blockchain.scripthash.subscribe", scriptHashOf(t, "aa"), nil)
	require.Equal(t, ports.ChainEvent{Script: "aa"}, next(t, sub), "the ones before it say nothing")
}

func TestSubscribeBatchesInChunks(t *testing.T) {
	srv := newChain(t, 100)
	w := newTestWatcher(t, srv)
	scripts := make([]string, 700)
	for i := range scripts {
		scripts[i] = fmt.Sprintf("5120%064x", i)
	}
	sub, err := w.Subscribe(t.Context(), scripts)
	require.NoError(t, err)
	defer sub.Stop()
	require.NotNil(t, next(t, sub).Tip)
	seen := map[string]bool{}
	for range scripts {
		seen[next(t, sub).Script] = true
	}
	require.Len(t, seen, 700)
	require.Equal(t, []int{345, 345, 10}, srv.batchSizes())
}

func TestUpdateSubscribesAddedAndUnsubscribesRemoved(t *testing.T) {
	srv := newChain(t, 100)
	srv.status = map[string]any{scriptHashOf(t, "bb"): "s-bb"}
	w := newTestWatcher(t, srv)
	sub, err := w.Subscribe(t.Context(), []string{"aa"})
	require.NoError(t, err)
	defer sub.Stop()
	for range 2 {
		next(t, sub)
	}

	require.NoError(t, sub.Update(t.Context(), []string{"bb"}, []string{"aa"}))
	require.Equal(t, ports.ChainEvent{Script: "bb", Status: "s-bb"}, next(t, sub))
	require.Equal(t, []string{scriptHashOf(t, "aa")}, srv.paramsOf("blockchain.scripthash.unsubscribe"))
	srv.push("blockchain.scripthash.subscribe", scriptHashOf(t, "aa"), "late")
	srv.push("blockchain.scripthash.subscribe", scriptHashOf(t, "bb"), "s2")
	require.Equal(t, ports.ChainEvent{Script: "bb", Status: "s2"}, next(t, sub), "a removed script is not reported")
	require.Error(t, sub.Update(t.Context(), []string{"zz"}, nil))
	require.Error(t, sub.Update(t.Context(), nil, []string{"zz"}))

	sub.Stop()
	_, err = w.Subscribe(t.Context(), nil)
	require.NoError(t, err, "a stopped subscription can be replaced")
}

func TestReconnectSubscribesAgainAndReportsStatuses(t *testing.T) {
	srv := newChain(t, 100)
	srv.status = map[string]any{scriptHashOf(t, "aa"): "s1", scriptHashOf(t, "bb"): "t1"}
	w := newTestWatcher(t, srv)
	sub, err := w.Subscribe(t.Context(), []string{"aa", "bb"})
	require.NoError(t, err)
	defer sub.Stop()
	for range 3 {
		next(t, sub)
	}

	srv.setStatus(scriptHashOf(t, "aa"), "s2")
	srv.height = 103
	srv.drop()
	tip := next(t, sub).Tip
	require.NotNil(t, tip)
	require.Equal(t, int64(103), tip.Height)
	statuses := map[string]string{}
	for range 2 {
		ev := next(t, sub)
		statuses[ev.Script] = ev.Status
	}
	require.Equal(t, map[string]string{"aa": "s2", "bb": "t1"}, statuses, "every script reports its status again")
	require.Equal(t, 2, srv.connections())
	require.Len(t, srv.paramsOf("server.version"), 2, "the handshake is repeated")
}

func TestReconnectKeepsTryingUntilTheServerReturns(t *testing.T) {
	srv := newChain(t, 100)
	w := newTestWatcher(t, srv)
	sub, err := w.Subscribe(t.Context(), []string{"aa"})
	require.NoError(t, err)
	defer sub.Stop()
	for range 2 {
		next(t, sub)
	}

	srv.stopListening()
	srv.drop()
	_, err = w.Unspents(t.Context(), "aa")
	require.ErrorIs(t, err, ports.ErrDisconnected)
	time.Sleep(50 * time.Millisecond)
	srv.listen()
	require.Equal(t, int64(100), next(t, sub).Tip.Height)
	require.Equal(t, "aa", next(t, sub).Script)
}

func TestPingKeepsTheConnectionBusy(t *testing.T) {
	srv := newChain(t, 100)
	w, err := newWatcher(srv.url(), timings{request: time.Second, ping: 20 * time.Millisecond, backoff: 10 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	require.Eventually(t, func() bool { return len(srv.paramsOf("server.ping")) >= 3 }, 2*time.Second, 10*time.Millisecond)
}

func TestSilentServerDropsTheConnection(t *testing.T) {
	srv := newChain(t, 100)
	srv.silent = "server.ping"
	w, err := newWatcher(srv.url(), timings{request: 50 * time.Millisecond, ping: 20 * time.Millisecond, backoff: 10 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	require.Eventually(t, func() bool { return srv.connections() >= 2 }, 2*time.Second, 10*time.Millisecond)
}

func TestRequestTimesOut(t *testing.T) {
	srv := newChain(t, 100)
	srv.silent = "blockchain.transaction.get"
	w, err := newWatcher(srv.url(), timings{request: 50 * time.Millisecond, ping: time.Hour, backoff: 10 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(w.Close)
	_, err = w.Transaction(t.Context(), "tx")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestTransaction(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: [32]byte{1}}})
	tx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	srv := newServer(t, func(method string, params []any) (any, *rpcError) {
		if method == "blockchain.transaction.get" {
			return hex.EncodeToString(buf.Bytes()), nil
		}
		return nil, nil
	})
	w := newTestWatcher(t, srv)

	got, err := w.Transaction(t.Context(), tx.TxHash().String())
	require.NoError(t, err)
	require.Equal(t, tx.TxHash(), got.TxHash())
}

func TestTransactionRefusesGarbage(t *testing.T) {
	answer := any("zz")
	srv := newServer(t, func(string, []any) (any, *rpcError) { return answer, nil })
	w := newTestWatcher(t, srv)
	_, err := w.Transaction(t.Context(), "t")
	require.Error(t, err)
	answer = "0100"
	_, err = w.Transaction(t.Context(), "t")
	require.Error(t, err)
	answer = 5
	_, err = w.Transaction(t.Context(), "t")
	require.Error(t, err)
}

func TestTipNearGenesisUsesWhatThereIs(t *testing.T) {
	srv := newChain(t, 2)
	w := newTestWatcher(t, srv)
	tip, err := w.Tip(t.Context())
	require.NoError(t, err)
	require.Equal(t, int64(2), tip.Height)
	require.Equal(t, time.Unix(1_700_000_010, 0), tip.MedianTime)
}

func TestTipRefusesMalformedHeaders(t *testing.T) {
	srv := newChain(t, 100)
	srv.headersHex = "abcd"
	w := newTestWatcher(t, srv)
	_, err := w.Tip(t.Context())
	require.ErrorContains(t, err, "malformed")
}

func TestDialRefusesWhatIsNotAnElectrumURL(t *testing.T) {
	for _, url := range []string{"", "localhost:50001", "http://localhost:50001", "tcp://"} {
		_, err := NewWatcher(url)
		require.Error(t, err, url)
	}
	_, err := NewWatcher("tcp://127.0.0.1:1")
	require.Error(t, err, "nothing listens")
}

func TestTLSURLsHandshake(t *testing.T) {
	srv := newChain(t, 100)
	for _, scheme := range []string{"ssl", "tls"} {
		_, err := newWatcher(scheme+"://"+srv.addr(), timings{request: 100 * time.Millisecond})
		require.Error(t, err, "the plain stand-in does not speak TLS")
	}
}

func TestServerVersionRefused(t *testing.T) {
	srv := newServer(t, func(string, []any) (any, *rpcError) { return nil, &rpcError{Code: 1, Message: "no"} })
	_, err := NewWatcher(srv.url())
	require.ErrorContains(t, err, "server.version")
}

func next(t *testing.T, sub ports.ChainSubscription) ports.ChainEvent {
	t.Helper()
	select {
	case ev := <-sub.Events():
		return ev
	case <-time.After(3 * time.Second):
		require.FailNow(t, "no event")
		return ports.ChainEvent{}
	}
}

func scriptHashOf(t *testing.T, script string) string {
	t.Helper()
	h, err := scriptHash(script)
	if err != nil {
		return script
	}
	return h
}

func newTestWatcher(t *testing.T, srv *server) *Watcher {
	t.Helper()
	w, err := newWatcher(srv.url(), fast)
	require.NoError(t, err)
	t.Cleanup(w.Close)
	return w
}

// server stands in for an Electrum server: line-delimited JSON-RPC, batches answered as arrays.
type server struct {
	handle func(method string, params []any) (any, *rpcError)
	addrs  string

	mu      sync.Mutex
	ln      net.Listener
	conns   []net.Conn
	opened  int
	calls   []recorded
	batches []int

	// newChain fills these
	height     int64
	status     map[string]any
	headersHex string
	silent     string // a method that never gets an answer
}

type recorded struct {
	method string
	params []any
}

func newServer(t *testing.T, handle func(string, []any) (any, *rpcError)) *server {
	t.Helper()
	s := &server{handle: handle}
	s.listen()
	t.Cleanup(func() { s.stopListening(); s.drop() })
	return s
}

// newChain answers like a node at height: headers whose times grow by ten seconds a block.
func newChain(t *testing.T, height int64) *server {
	t.Helper()
	var s *server
	s = newServer(t, func(method string, params []any) (any, *rpcError) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch method {
		case "server.version":
			return []string{"fake", "1.4"}, nil
		case "server.ping":
			return nil, nil
		case "blockchain.headers.subscribe":
			return map[string]any{"height": s.height, "hex": ""}, nil
		case "blockchain.block.headers":
			if s.headersHex != "" {
				return map[string]any{"count": 1, "hex": s.headersHex}, nil
			}
			start, count := int64(params[0].(float64)), int64(params[1].(float64))
			var raw []byte
			for h := start; h < start+count; h++ {
				header := make([]byte, headerSize)
				binary.LittleEndian.PutUint32(header[timeOffset:], uint32(1_700_000_000+h*10))
				raw = append(raw, header...)
			}
			return map[string]any{"count": count, "hex": hex.EncodeToString(raw)}, nil
		case "blockchain.scripthash.subscribe":
			return s.status[params[0].(string)], nil
		}
		return nil, nil
	})
	s.height = height
	s.status = map[string]any{}
	return s
}

func (s *server) url() string  { return "tcp://" + s.addr() }
func (s *server) addr() string { return s.addrs }

func (s *server) listen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr := s.addrs
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	s.ln, s.addrs = ln, ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.opened++
			s.mu.Unlock()
			go s.serve(conn)
		}
	}()
}

func (s *server) stopListening() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *server) serve(conn net.Conn) {
	var wmu sync.Mutex
	write := func(v any) {
		raw, _ := json.Marshal(v)
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = conn.Write(append(raw, '\n'))
	}
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		if line[0] == '[' {
			var reqs []request
			_ = json.Unmarshal(line, &reqs)
			s.mu.Lock()
			s.batches = append(s.batches, len(reqs))
			s.mu.Unlock()
			replies := make([]any, 0, len(reqs))
			for _, req := range reqs {
				replies = append(replies, s.answer(req))
			}
			write(replies)
			continue
		}
		var req request
		_ = json.Unmarshal(line, &req)
		go func() {
			if reply := s.answer(req); reply != nil {
				write(reply)
			}
		}()
	}
}

func (s *server) answer(req request) map[string]any {
	s.mu.Lock()
	s.calls = append(s.calls, recorded{req.Method, req.Params})
	silent := s.silent
	s.mu.Unlock()
	if req.Method == silent {
		return nil
	}
	result, rpcErr := s.handle(req.Method, req.Params)
	if rpcErr != nil {
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": rpcErr}
	}
	return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
}

func (s *server) push(method string, params ...any) {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_, _ = c.Write(append(raw, '\n'))
	}
}

func (s *server) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

func (s *server) setStatus(hash string, status any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status[hash] = status
}

func (s *server) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opened
}

func (s *server) batchSizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.batches)
}

func (s *server) paramsOf(method string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.calls {
		if c.method == method {
			out = append(out, fmt.Sprint(c.params[0:min(1, len(c.params))]...))
		}
	}
	return out
}
