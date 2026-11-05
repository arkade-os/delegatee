package config

import (
	"context"
	"fmt"

	delegationapp "github.com/arkade-os/delegatee/internal/core/application/delegation"
	executionapp "github.com/arkade-os/delegatee/internal/core/application/execution"
	"github.com/arkade-os/delegatee/internal/core/application/health"
	"github.com/arkade-os/delegatee/internal/core/application/registry"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/internal/infrastructure/arkd"
	"github.com/arkade-os/delegatee/internal/infrastructure/electrum"
	"github.com/arkade-os/delegatee/internal/infrastructure/emulator"
	"github.com/arkade-os/delegatee/internal/infrastructure/postgres"
	grpcserver "github.com/arkade-os/delegatee/internal/interface/grpc"
	"github.com/arkade-os/delegatee/internal/interface/grpc/handlers"
	"github.com/arkade-os/delegatee/templates"
	log "github.com/sirupsen/logrus"
)

// Daemon is the composition root: the services wired to postgres, arkd, electrum and the emulator behind the gRPC server.
type Daemon struct {
	Server  *grpcserver.Server
	closers []func()
}

func NewDaemon(ctx context.Context, cfg Config) (_ *Daemon, err error) {
	d := &Daemon{}
	defer func() {
		if err != nil {
			d.Stop()
		}
	}()
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, func() { _ = db.Close() })
	ark, indexer, chain, emu, err := d.connect(cfg)
	if err != nil {
		return nil, err
	}
	arkInfo, err := ark.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("arkd info: %w", err)
	}
	emuInfo, err := emu.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("emulator info: %w", err)
	}

	reg := registry.NewService(db.Artifacts(), db.Templates(), registry.Limits{
		MaxArtifacts: cfg.MaxArtifacts, MaxTemplates: cfg.MaxTemplates, MaxDocumentBytes: cfg.MaxDocumentBytes,
	})
	if cfg.DefaultTemplates {
		if err := reg.RegisterDefaults(ctx, templates.Artifacts, templates.Templates); err != nil {
			return nil, fmt.Errorf("default templates: %w", err)
		}
	}
	delegations := delegationapp.NewService(
		reg, db.Delegations(), db.Streams(), indexer, cfg.CosignerKey.PubKey(), cfg.EncryptionKey, arkInfo.SignerPubkey, emuInfo.SignerPubkey, arkInfo.Network,
		delegationapp.Limits{
			MinDelegationExpiry: cfg.MinDelegationExpiry, MaxDelegations: cfg.MaxDelegations, MaxStreamChildren: cfg.MaxStreamChildren,
			ExpiryInterval: cfg.ExpiryInterval, PruneAfter: cfg.PruneAfter,
		},
	)
	if cfg.DefaultTemplates {
		delegations.StartStreams(ctx, templates.Templates)
	}
	delegations.Start(context.Background())
	d.closers = append(d.closers, delegations.Stop)
	execution := executionapp.NewService(delegations, reg, ark, indexer, chain, emu, cfg.CosignerKey, db.Coins(), db.Attempts(), db.Summaries(), executionapp.Limits{
		OffchainConcurrency: cfg.OffchainConcurrency, AttemptTimeout: cfg.AttemptTimeout, RetryDelay: cfg.RetryDelay,
		IntentsPerBatch: cfg.IntentsPerBatch, IntentTimeout: cfg.IntentTimeout, Reserve: cfg.Reserve,
		BanDuration: cfg.BanDuration, LandingWindow: cfg.LandingWindow,
		TemplateMaxFailures: cfg.TemplateMaxFailures, LoopStall: cfg.LoopStall,
	})
	if err := execution.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("start execution: %w", err)
	}
	if len(cfg.AdminUsers) == 0 {
		log.Warn("admin port serves without authentication")
	}
	checker := health.NewChecker(db, ark, emu, execution)
	server, err := grpcserver.Listen(
		ctx, grpcserver.Options{
			PublicPort: cfg.Port, AdminPort: cfg.AdminPort, PublicRateLimit: cfg.PublicRateLimit, Users: cfg.AdminUsers,
			Status: execution, Health: checker,
		},
		handlers.NewDelegatee(reg, delegations, execution, cfg.Version), handlers.NewAdmin(reg, delegations, execution, checker),
	)
	if err != nil {
		execution.Stop()
		return nil, err
	}
	d.Server = server
	// the loop stops before the server, so nothing moves while the last requests are answered
	d.closers = append(d.closers, server.Stop, execution.Stop)
	return d, nil
}

// connect returns the configured stand-ins or dials the URLs.
func (d *Daemon) connect(cfg Config) (ports.Signer, ports.Indexer, ports.ChainWatcher, ports.Emulator, error) {
	ark, indexer, chain, emu := cfg.Ark, cfg.Indexer, cfg.Chain, cfg.Emulator
	if ark == nil || indexer == nil {
		c, err := arkd.NewClient(cfg.ArkURL)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		d.closers = append(d.closers, c.Close)
		if ark == nil {
			ark = c
		}
		if indexer == nil {
			indexer = c
		}
	}
	if chain == nil {
		c, err := electrum.NewWatcher(cfg.ElectrumURL)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		d.closers = append(d.closers, c.Close)
		chain = c
	}
	if emu == nil {
		c, err := emulator.NewClient(cfg.EmulatorURL)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		d.closers = append(d.closers, func() { _ = c.Close() })
		emu = c
	}
	return ark, indexer, chain, emu, nil
}

// Stop runs the closers newest first, so the server stops before the database.
func (d *Daemon) Stop() {
	for i := len(d.closers) - 1; i >= 0; i-- {
		d.closers[i]()
	}
	d.closers = nil
}
