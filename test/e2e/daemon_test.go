//go:build e2e

// Package e2e drives the daemon in-process against the regtest stack; run `make regtest-up` then
// `make test-e2e`.
package e2e

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/arkade-os/executor/internal/config"
	"github.com/arkade-os/executor/test/daemon"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	arkURL       = "localhost:7070"
	emulatorURL  = "localhost:7073"
	electrumURL  = "tcp://localhost:50001"
	explorerURL  = "http://localhost:3000"
	arkdAdminURL = "http://localhost:7071"
	password     = "password"
)

type executor struct {
	cfg     config.Config
	client  executorv1.ExecutorServiceClient
	admin   executorv1.AdminServiceClient
	indexer clientlib.Indexer
	url     string // public REST base
	stop    func() // returns once the batch in flight has ended
}

// start boots a daemon over an empty database; the tweaks adjust its config.
func start(t *testing.T, tweak ...func(*config.Config)) executor {
	t.Helper()
	cosigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	encryption, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	cfg := config.Default()
	cfg.Version, cfg.DatabaseURL, cfg.ArkURL, cfg.EmulatorURL, cfg.ElectrumURL = "e2e", daemon.DatabaseURL(), arkURL, emulatorURL, electrumURL
	cfg.MaxDelegations, cfg.RetryDelay, cfg.PruneAfter, cfg.PublicRateLimit = 50_000, 5*time.Second, 0, 0
	cfg.CosignerKey, cfg.EncryptionKey = cosigner, encryption
	daemon.ResetDatabase(t, cfg.DatabaseURL)
	return boot(t, cfg, tweak)
}

// restart boots another daemon over the database of d.
func (d executor) restart(t *testing.T, tweak ...func(*config.Config)) executor {
	t.Helper()
	return boot(t, d.cfg, tweak)
}

func boot(t *testing.T, cfg config.Config, tweak []func(*config.Config)) executor {
	t.Helper()
	cfg.Port, cfg.AdminPort = daemon.FreePort(t), daemon.FreePort(t)
	for _, f := range tweak {
		f(&cfg)
	}
	d, err := config.NewDaemon(context.Background(), cfg)
	require.NoError(t, err)
	go func() { _ = d.Server.Serve() }()
	t.Cleanup(d.Stop)

	idx, err := indexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(idx.Close)
	return executor{
		cfg:     cfg,
		indexer: idx,
		stop:    d.Stop,
		url:     "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)),
		client:  executorv1.NewExecutorServiceClient(daemon.Dial(t, d.Server.PublicAddr())),
		admin:   executorv1.NewAdminServiceClient(daemon.Dial(t, d.Server.AdminAddr())),
	}
}
