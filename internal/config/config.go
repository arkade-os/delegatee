package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
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
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const envPrefix = "DELEGATEE_"

const maxSecretKeys = 16

type AdminUser struct {
	Username     string
	PasswordHash string
}

type Config struct {
	ArkURL           string
	EmulatorURL      string // https:// enables TLS
	DatabaseURL      string
	Port             uint32
	AdminPort        uint32
	LogLevel         int
	SecretKey        *btcec.PrivateKey   // active tree cosigner key, pinned in new covenants
	SecretKeys       []*btcec.PrivateKey // active key followed by previous keys
	PollInterval     time.Duration
	CollectionWindow time.Duration // maximum extra wait from renewal eligibility; zero disables
	RenewalTimeout   time.Duration // must cover the gap between two arkd sessions
	// MaxVtxosPerIntent: the covenant runs 4 OP_INSPECTINTENTMESSAGE per input
	// and the emulator allows 64 per request, so 16 is the ceiling.
	MaxVtxosPerIntent int
	// MaxDelegations caps active delegations, so that flooding the public
	// API cannot delay the renewals of the ones already registered.
	MaxDelegations int
	// PublicRateLimit is the requests per second one client IP may make on
	// the public port, with a burst of ten times that. 0 disables it.
	PublicRateLimit float64
	// AdminUsers are used on the admin port when auth mode is file.
	AdminUsers []AdminUser
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
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%sPORT must be between 1 and 65535", envPrefix)
	}
	adminPort, err := envInt("ADMIN_PORT", 7081)
	if err != nil {
		return nil, err
	}
	cfg.AdminPort = uint32(adminPort)
	if adminPort < 1 || adminPort > 65535 {
		return nil, fmt.Errorf("%sADMIN_PORT must be between 1 and 65535", envPrefix)
	}
	if cfg.LogLevel, err = envInt("LOG_LEVEL", 4); err != nil {
		return nil, err
	}
	if cfg.PollInterval, err = envDuration("POLL_INTERVAL", time.Minute); err != nil {
		return nil, err
	}
	if cfg.PollInterval <= 0 {
		return nil, fmt.Errorf("%sPOLL_INTERVAL must be positive", envPrefix)
	}
	if cfg.RenewalTimeout, err = envDuration("RENEWAL_TIMEOUT", 2*time.Hour); err != nil {
		return nil, err
	}
	if cfg.RenewalTimeout <= 0 {
		return nil, fmt.Errorf("%sRENEWAL_TIMEOUT must be positive", envPrefix)
	}
	if cfg.CollectionWindow, err = envDuration("COLLECTION_WINDOW", 30*time.Second); err != nil {
		return nil, err
	}
	if cfg.CollectionWindow < 0 {
		return nil, fmt.Errorf("%sCOLLECTION_WINDOW must not be negative", envPrefix)
	}
	if cfg.MaxVtxosPerIntent, err = envInt("MAX_VTXOS_PER_INTENT", 16); err != nil {
		return nil, err
	}
	if cfg.MaxVtxosPerIntent <= 0 || cfg.MaxVtxosPerIntent > application.MaxVtxosPerIntent {
		return nil, fmt.Errorf("%sMAX_VTXOS_PER_INTENT must be between 1 and %d", envPrefix, application.MaxVtxosPerIntent)
	}
	if cfg.MaxDelegations, err = envInt("MAX_DELEGATIONS", 50_000); err != nil {
		return nil, err
	}
	if cfg.MaxDelegations <= 0 {
		return nil, fmt.Errorf("%sMAX_DELEGATIONS must be positive", envPrefix)
	}
	if cfg.PublicRateLimit, err = envFloat("PUBLIC_RATE_LIMIT", 5); err != nil {
		return nil, err
	}
	if cfg.SecretKeys, err = loadSecretKeys(); err != nil {
		return nil, err
	}
	cfg.SecretKey = cfg.SecretKeys[0]
	authMode := os.Getenv(envPrefix + "ADMIN_AUTH")
	usersFile := os.Getenv(envPrefix + "ADMIN_USERS_FILE")
	if authMode == "" && usersFile != "" {
		authMode = "file"
	}
	switch authMode {
	case "file":
		if usersFile == "" {
			return nil, fmt.Errorf("%sADMIN_USERS_FILE is required when ADMIN_AUTH=file", envPrefix)
		}
		if cfg.AdminUsers, err = loadAdminUsers(usersFile); err != nil {
			return nil, err
		}
	case "disabled":
		if usersFile != "" {
			return nil, fmt.Errorf("%sADMIN_USERS_FILE cannot be set when ADMIN_AUTH=disabled", envPrefix)
		}
	default:
		return nil, fmt.Errorf("%sADMIN_AUTH must be file or disabled", envPrefix)
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
		_ = repo.Close()
		return nil, fmt.Errorf("connect to arkd: %w", err)
	}
	indexerSvc, err := grpcindexer.NewClient(arkURL)
	if err != nil {
		_ = repo.Close()
		ark.Close()
		return nil, fmt.Errorf("connect to indexer: %w", err)
	}
	emuURL, creds := grpcTarget(c.EmulatorURL)
	emuConn, err := grpc.NewClient(emuURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		_ = repo.Close()
		ark.Close()
		indexerSvc.Close()
		return nil, fmt.Errorf("connect to emulator: %w", err)
	}
	keys := c.SecretKeys
	if len(keys) == 0 && c.SecretKey != nil {
		keys = []*btcec.PrivateKey{c.SecretKey}
	}
	svc, err := application.NewServiceWithKeys(
		ctx, repo, ark, indexerSvc, emulatorclient.NewGRPCClient(emuConn),
		keys, c.PollInterval, c.RenewalTimeout, c.CollectionWindow, c.MaxVtxosPerIntent, c.MaxDelegations,
	)
	if err != nil {
		// main retries until arkd and the emulator are up: don't leak a pool per attempt
		_ = repo.Close()
		_ = emuConn.Close()
		ark.Close()
		indexerSvc.Close()
		return nil, err
	}
	return svc, nil
}

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

func loadSecretKeys() ([]*btcec.PrivateKey, error) {
	if path := os.Getenv(envPrefix + "SECRET_KEYS_FILE"); path != "" {
		if os.Getenv(envPrefix+"SECRET_KEY") != "" || os.Getenv(envPrefix+"SECRET_KEY_FILE") != "" || os.Getenv(envPrefix+"PREVIOUS_SECRET_KEYS") != "" {
			return nil, fmt.Errorf("%sSECRET_KEYS_FILE cannot be combined with individual secret key settings", envPrefix)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%sSECRET_KEYS_FILE: %w", envPrefix, err)
		}
		lines := strings.Split(string(content), "\n")
		keys := make([]*btcec.PrivateKey, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, err := parseSecretKey(line)
			if err != nil {
				return nil, fmt.Errorf("%sSECRET_KEYS_FILE: %w", envPrefix, err)
			}
			keys = append(keys, key)
		}
		return validateSecretKeys(keys)
	}
	active, err := loadSecretKey()
	if err != nil {
		return nil, err
	}
	keys := []*btcec.PrivateKey{active}
	for _, value := range strings.Split(os.Getenv(envPrefix+"PREVIOUS_SECRET_KEYS"), ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key, err := parseSecretKey(value)
		if err != nil {
			return nil, fmt.Errorf("%sPREVIOUS_SECRET_KEYS: %w", envPrefix, err)
		}
		keys = append(keys, key)
	}
	return validateSecretKeys(keys)
}

func loadSecretKey() (*btcec.PrivateKey, error) {
	keyHex := os.Getenv(envPrefix + "SECRET_KEY")
	if path := os.Getenv(envPrefix + "SECRET_KEY_FILE"); path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%sSECRET_KEY_FILE: %w", envPrefix, err)
		}
		keyHex = strings.TrimSpace(string(content))
	}
	return parseSecretKey(keyHex)
}

func parseSecretKey(keyHex string) (*btcec.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%sSECRET_KEY must be 32 bytes hex", envPrefix)
	}
	key, _ := btcec.PrivKeyFromBytes(raw)
	if key.Key.IsZero() {
		return nil, fmt.Errorf("%sSECRET_KEY must not be zero", envPrefix)
	}
	return key, nil
}

func validateSecretKeys(keys []*btcec.PrivateKey) ([]*btcec.PrivateKey, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%sSECRET_KEYS_FILE must contain at least one key", envPrefix)
	}
	if len(keys) > maxSecretKeys {
		return nil, fmt.Errorf("%sSECRET_KEYS_FILE must contain at most %d keys", envPrefix, maxSecretKeys)
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		pub := hex.EncodeToString(key.PubKey().SerializeCompressed())
		if _, ok := seen[pub]; ok {
			return nil, fmt.Errorf("%ssecret keys contain a duplicate key", envPrefix)
		}
		seen[pub] = struct{}{}
	}
	return keys, nil
}

func loadAdminUsers(path string) ([]AdminUser, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%sADMIN_USERS_FILE: %w", envPrefix, err)
	}
	users := make([]AdminUser, 0)
	seen := map[string]struct{}{}
	for lineNumber, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		username, passwordHash, ok := strings.Cut(line, ":")
		if !ok || username == "" || strings.ContainsAny(username, "\r\n:") || passwordHash == "" {
			return nil, fmt.Errorf("%sADMIN_USERS_FILE line %d must be username:bcrypt-hash", envPrefix, lineNumber+1)
		}
		if _, ok := seen[username]; ok {
			return nil, fmt.Errorf("%sADMIN_USERS_FILE contains duplicate user %q", envPrefix, username)
		}
		cost, err := bcrypt.Cost([]byte(passwordHash))
		if err != nil || cost < bcrypt.DefaultCost {
			return nil, fmt.Errorf("%sADMIN_USERS_FILE line %d has an invalid bcrypt hash", envPrefix, lineNumber+1)
		}
		seen[username] = struct{}{}
		users = append(users, AdminUser{Username: username, PasswordHash: passwordHash})
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%sADMIN_USERS_FILE must contain at least one user", envPrefix)
	}
	return users, nil
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

func envFloat(key string, def float64) (float64, error) {
	s := os.Getenv(envPrefix + key)
	if s == "" {
		return def, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, fmt.Errorf("%s%s must be a non-negative number", envPrefix, key)
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
