package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/arkade-os/delegatee/internal/config"
	log "github.com/sirupsen/logrus"
)

var Version = "dev"

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	cfg, err := config.Load()
	if err != nil {
		log.WithError(err).Fatal("invalid config")
	}
	cfg.Version = Version
	log.SetLevel(log.Level(cfg.LogLevel))
	log.WithField("version", Version).Info("starting delegateed")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	daemon, err := config.NewDaemon(ctx, cfg)
	if err != nil {
		log.WithError(err).Fatal("start daemon")
	}
	go func() {
		<-ctx.Done()
		log.Info("shutting down delegateed")
		daemon.Stop()
	}()
	if err := daemon.Server.Serve(); err != nil {
		log.WithError(err).Fatal("serve")
	}
}
