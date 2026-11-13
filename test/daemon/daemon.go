// Package daemon boots executord in-process against the real postgres, with stand-ins for arkd,
// electrum and the emulator; it is the gate every slice passes.
package daemon

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/arkade-os/executor/internal/config"
	"github.com/arkade-os/executor/internal/infrastructure/arkd"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Daemon struct {
	Client   executorv1.ExecutorServiceClient
	Admin    executorv1.AdminServiceClient
	RestURL  string
	AdminURL string
	DB       *sql.DB
	Server   *btcec.PublicKey
	Emulator *btcec.PublicKey
	Cosigner *btcec.PublicKey
	Arkd     *ark
	Chain    *chain
	Emu      *emulator
	dsn      string
	stop     func()
}

// Start resets the database, boots the daemon on free ports and stops it with the test.
// Defaults are off and the admin port takes no credentials unless an option says otherwise.
func Start(t *testing.T, opts ...func(*config.Config)) *Daemon {
	t.Helper()
	dsn := DatabaseURL()
	standin, chain := newArk(), newChain()
	standin.chain = chain
	return boot(
		t, dsn, ResetDatabase(t, dsn), standin, chain,
		&emulator{signer: newKey(3).PubKey(), ark: standin}, opts,
	)
}

// DatabaseURL is the postgres the suites run against.
func DatabaseURL() string {
	if dsn := os.Getenv("EXECUTOR_DATABASE_URL"); dsn != "" {
		return dsn
	}
	return "postgres://postgres@localhost:5432/executor?sslmode=disable"
}

// ResetDatabase empties the database at dsn and keeps it open until the test ends.
func ResetDatabase(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.ExecContext(t.Context(), "DROP SCHEMA public CASCADE; CREATE SCHEMA public")
	require.NoError(t, err)
	return db
}

// ScriptNum is n as the hex of a script number, how templates take their integers.
func ScriptNum(n int64) string {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return hex.EncodeToString(b)
}

// Stop shuts the daemon down, leaving the database and the stand-ins as they are.
func (d *Daemon) Stop() { d.stop() }

// Restart stops the daemon and boots another over the same database and stand-ins, their counters
// reset.
func (d *Daemon) Restart(t *testing.T, opts ...func(*config.Config)) *Daemon {
	t.Helper()
	d.stop()
	d.Arkd.mu.Lock()
	d.Arkd.SubscriptionSizes, d.Arkd.VtxosChunks, d.Arkd.Submitted = nil, nil, nil
	d.Arkd.mu.Unlock()
	d.Chain.ResetCalls()
	return boot(t, d.dsn, d.DB, d.Arkd, d.Chain, d.Emu, opts)
}

// WithRetryDelay is how long the coins of a failed attempt wait before another.
func WithRetryDelay(d time.Duration) func(*config.Config) {
	return func(c *config.Config) { c.RetryDelay = d }
}

// WithBanDuration is how long the coins of an intent a batch failed on keep out of the queue.
func WithBanDuration(d time.Duration) func(*config.Config) {
	return func(c *config.Config) { c.BanDuration = d }
}

// WithLandingWindow is how long a restarted daemon waits to see the coins of forfeited intents
// spent.
func WithLandingWindow(d time.Duration) func(*config.Config) {
	return func(c *config.Config) { c.LandingWindow = d }
}

// WithTemplateMaxFailures is how many failed attempts in a row disable a template.
func WithTemplateMaxFailures(n int) func(*config.Config) {
	return func(c *config.Config) { c.TemplateMaxFailures = n }
}

// WithEncryptionKey lets templates with secrets be registered.
func WithEncryptionKey(c *config.Config) { c.EncryptionKey = newKey(9) }

// WithDefaultTemplates registers the daemon's own templates and starts their streams.
func WithDefaultTemplates(c *config.Config) { c.DefaultTemplates = true }

// WithMaxDelegations caps the active delegations clients register and, apart from them, the ones
// streams spawn.
func WithMaxDelegations(clients, spawned int) func(*config.Config) {
	return func(c *config.Config) { c.MaxDelegations, c.MaxStreamChildren = clients, spawned }
}

// WithDelegationExpiry sets the shortest delegation lifetime, how often expired delegations are
// marked and how long after expiry a spawned one is deleted.
func WithDelegationExpiry(min, interval, pruneAfter time.Duration) func(*config.Config) {
	return func(c *config.Config) {
		c.MinDelegationExpiry, c.ExpiryInterval, c.PruneAfter = min, interval, pruneAfter
	}
}

// WithVtxosDelay makes every GetVtxos answer take d.
func WithVtxosDelay(d time.Duration) func(*config.Config) {
	return func(c *config.Config) { c.Ark.(*ark).vtxosDelay = d }
}

// WithPublicRateLimit caps the requests per second one client address may send to the public port.
func WithPublicRateLimit(perSecond int) func(*config.Config) {
	return func(c *config.Config) { c.PublicRateLimit = perSecond }
}

// WithAdminUser protects the admin port with one user, through a users file as in production.
func WithAdminUser(t *testing.T, name, password string) func(*config.Config) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "users")
	require.NoError(t, os.WriteFile(path, []byte(name+":"+string(hash)+"\n"), 0o600))
	users, err := config.LoadAdminUsers(path)
	require.NoError(t, err)
	return func(c *config.Config) { c.AdminUsers = users }
}

// Dial connects to a gRPC server in the clear and closes with the test.
func Dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// FreePort is a TCP port nothing listens on.
func FreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// TLV encodes values as records tagged from 1: tag[1] || length[2, big-endian] || value.
func TLV(values ...[]byte) []byte {
	var b []byte
	for i, v := range values {
		b = append(b, byte(i+1))
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
		b = append(b, v...)
	}
	return b
}

// EnforcePayTo is covclaimd's covenant: the first output pays program at least the input's value.
func EnforcePayTo(t *testing.T, program []byte) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_DUP).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).AddData(program).AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_GREATERTHANOREQUAL).Script()
	require.NoError(t, err)
	return s
}

func boot(
	t *testing.T, dsn string, db *sql.DB, standin *ark, chain *chain, emu *emulator,
	opts []func(*config.Config),
) *Daemon {
	t.Helper()
	server, cosigner := newKey(1), newKey(4)
	cfg := config.Default()
	cfg.Version, cfg.DatabaseURL, cfg.Port, cfg.AdminPort = "test", dsn, FreePort(t), FreePort(t)
	cfg.MaxDelegations, cfg.PruneAfter, cfg.PublicRateLimit, cfg.DefaultTemplates = 1000, 0, 0, false
	cfg.CosignerKey, cfg.Ark, cfg.Indexer, cfg.Chain, cfg.Emulator = cosigner, standin, arkd.NewIndexer(
		standin,
		standin,
	), chain, emu
	for _, opt := range opts {
		opt(&cfg)
	}
	standin.once.Do(func() { go standin.runSessions(t.Context()) })
	d, err := config.NewDaemon(context.Background(), cfg)
	require.NoError(t, err)
	go func() { _ = d.Server.Serve() }()
	t.Cleanup(d.Stop)

	conn := Dial(t, d.Server.PublicAddr())
	adminConn := Dial(t, d.Server.AdminAddr())
	return &Daemon{
		Client:   executorv1.NewExecutorServiceClient(conn),
		Admin:    executorv1.NewAdminServiceClient(adminConn),
		RestURL:  "http://127.0.0.1:" + strconv.Itoa(cfg.Port),
		AdminURL: "http://127.0.0.1:" + strconv.Itoa(cfg.AdminPort),
		DB:       db,
		Server:   server.PubKey(),
		Emulator: emu.signer,
		Cosigner: cosigner.PubKey(),
		Arkd:     standin,
		Chain:    chain,
		Emu:      emu,
		dsn:      dsn,
		stop:     d.Stop,
	}
}
