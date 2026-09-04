package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/infrastructure/db/postgres"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const envPrefix = "DELEGATEE_"

type Config struct {
	ArkURL         string
	EmulatorURL    string // https:// enables TLS
	DatabaseURL    string
	Port           uint32
	AdminPort      uint32
	LogLevel       int
	SecretKey      *btcec.PrivateKey // tree cosigner key, pinned in the covenant
	PollInterval   time.Duration
	RenewalTimeout time.Duration // must cover the gap between two arkd sessions
	// MaxVtxosPerIntent: the covenant runs 4 OP_INSPECTINTENTMESSAGE per input
	// and the emulator allows 64 per request, so 16 is the ceiling.
	MaxVtxosPerIntent int
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		ArkURL:      os.Getenv(envPrefix + "ARK_URL"),
		EmulatorURL: os.Getenv(envPrefix + "EMULATOR_URL"),
		DatabaseURL: os.Getenv(envPrefix + "DATABASE_URL"),
	}
	for name, v := range map[string]string{
		"ARK_URL": cfg.ArkURL, "EMULATOR_URL": cfg.EmulatorURL, "DATABASE_URL": cfg.DatabaseURL,
	} {
		if v == "" {
			return nil, fmt.Errorf("%s%s is required", envPrefix, name)
		}
	}

	port, err := envInt("PORT", 7080)
	if err != nil {
		return nil, err
	}
	cfg.Port = uint32(port)
	adminPort, err := envInt("ADMIN_PORT", 7081)
	if err != nil {
		return nil, err
	}
	cfg.AdminPort = uint32(adminPort)
	if cfg.LogLevel, err = envInt("LOG_LEVEL", 4); err != nil {
		return nil, err
	}
	if cfg.PollInterval, err = envDuration("POLL_INTERVAL", time.Minute); err != nil {
		return nil, err
	}
	if cfg.RenewalTimeout, err = envDuration("RENEWAL_TIMEOUT", 2*time.Hour); err != nil {
		return nil, err
	}
	if cfg.MaxVtxosPerIntent, err = envInt("MAX_VTXOS_PER_INTENT", 16); err != nil {
		return nil, err
	}
	if cfg.SecretKey, err = loadSecretKey(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) AppService(ctx context.Context) (application.Service, error) {
	repo, err := postgres.NewRepository(ctx, c.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	arkURL := strings.TrimSuffix(c.ArkURL, "/")
	ark, err := grpcclient.NewClient(arkURL, "delegateed")
	if err != nil {
		return nil, fmt.Errorf("connect to arkd: %w", err)
	}
	indexerSvc, err := grpcindexer.NewClient(arkURL)
	if err != nil {
		return nil, fmt.Errorf("connect to indexer: %w", err)
	}
	emuURL, creds := grpcTarget(c.EmulatorURL)
	emuConn, err := grpc.NewClient(emuURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connect to emulator: %w", err)
	}
	return application.NewService(
		ctx, repo, ark, indexerSvc, emulatorclient.NewGRPCClient(emuConn),
		c.SecretKey, c.PollInterval, c.RenewalTimeout, c.MaxVtxosPerIntent,
	)
}

// grpcTarget turns a URL like https://host/ into host:443 with TLS, and
// http://host or host:port into a plaintext target, like the arkd client does.
func grpcTarget(url string) (string, credentials.TransportCredentials) {
	creds := insecure.NewCredentials()
	port := "80"
	if strings.HasPrefix(url, "https://") {
		creds = credentials.NewTLS(nil)
		port = "443"
	}
	target := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"), "/")
	if !strings.Contains(target, ":") {
		target += ":" + port
	}
	return target, creds
}

func loadSecretKey() (*btcec.PrivateKey, error) {
	raw, err := hex.DecodeString(os.Getenv(envPrefix + "SECRET_KEY"))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%sSECRET_KEY must be 32 bytes hex", envPrefix)
	}
	key, _ := btcec.PrivKeyFromBytes(raw)
	if key.Key.IsZero() {
		return nil, fmt.Errorf("%sSECRET_KEY must not be zero", envPrefix)
	}
	return key, nil
}

func envInt(key string, def int) (int, error) {
	s := os.Getenv(envPrefix + key)
	if s == "" {
		return def, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s%s must be an integer: %w", envPrefix, key, err)
	}
	return v, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	s := os.Getenv(envPrefix + key)
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s%s must be a duration: %w", envPrefix, key, err)
	}
	return d, nil
}
