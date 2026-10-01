package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arkade-os/delegatee/internal/config"
	"github.com/arkade-os/delegatee/internal/infrastructure/db/postgres"
	grpcservice "github.com/arkade-os/delegatee/internal/interface/grpc"
	log "github.com/sirupsen/logrus"
)

var Version = "dev"

func main() {
	log.SetFormatter(&log.JSONFormatter{})

	cfg, err := config.LoadConfig()
	if err != nil {
		log.WithError(err).Fatal("invalid config")
	}
	log.SetLevel(log.Level(cfg.LogLevel))
	log.WithField("version", Version).Info("starting delegateed")

	svc, err := grpcservice.NewService(Version, cfg)
	if err != nil {
		log.WithError(err).Fatal("init service")
	}

	for attempt := 1; ; attempt++ {
		if err = svc.Start(); err == nil {
			break
		}
		if attempt >= 30 || errors.Is(err, postgres.ErrKeyInUse) {
			log.WithError(err).Fatal("start service")
		}
		log.WithError(err).WithField("attempt", attempt).Warn("dependencies not ready, retrying in 5s")
		time.Sleep(5 * time.Second)
	}
	log.RegisterExitHandler(svc.Stop)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	log.Info("shutting down delegateed")
	log.Exit(0)
}
