package config

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/internal/infrastructure/db/postgres"
	"github.com/arkade-os/delegatee/internal/infrastructure/explorer"
	"github.com/arkade-os/delegatee/templates"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const envPrefix = "DELEGATEE_"

const maxDelegateKeys = 16

const lockCheckInterval = 10 * time.Second

type AdminUser struct {
	Username     string
	PasswordHash string
}

type Config struct {
	ArkURL      string
	EmulatorURL string // https:// enables TLS
	ExplorerURL string
	DatabaseURL string
	Port        uint32
	AdminPort   uint32
	LogLevel    int

	DelegateKeys   []*btcec.PrivateKey // delegate key of new delegations, then previous keys
	EncryptionKeys []*btcec.PrivateKey // first key published; retained keys decrypt existing secrets

	PollInterval        time.Duration
	OnchainPollInterval time.Duration
	CollectionWindow    time.Duration // maximum extra wait from renewal eligibility; zero disables
	RenewalTimeout      time.Duration // must cover the gap between two arkd sessions
	MinWatchExpiry      time.Duration // how far ahead a watch's expires_at must be; zero disables

	MaxOnchainFeeRate float64 // sat/vB cap on the explorer's fee rate for onchain templates
	// caps on what the public API stores, so flooding it cannot delay renewals
	MaxDelegations      int
	MaxTemplates        int
	MaxArtifacts        int
	MaxDocumentBytes    int
	TemplateMaxFailures int     // consecutive fully rejected renewal cycles that disable a template
	PublicRateLimit     float64 // requests per second per client IP on the public port, burst ten times that; 0 disables

	AdminUsers []AdminUser // empty leaves the admin port without authentication

	DefaultTemplates bool // register the documents of templates/ at startup, trusting the new templates
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		ExplorerURL: os.Getenv(envPrefix + "EXPLORER_URL"),
		ArkURL:      os.Getenv(envPrefix + "ARK_URL"),
		EmulatorURL: os.Getenv(envPrefix + "EMULATOR_URL"),
		DatabaseURL: os.Getenv(envPrefix + "DATABASE_URL"),
	}
	for name, v := range map[string]string{
		"ARK_URL": cfg.ArkURL, "EMULATOR_URL": cfg.EmulatorURL, "DATABASE_URL": cfg.DatabaseURL, "EXPLORER_URL": cfg.ExplorerURL,
	} {
		if v == "" {
			return nil, fmt.Errorf("%s%s is required", envPrefix, name)
		}
	}

	var err error
	if cfg.Port, err = envPort("PORT", 7080); err != nil {
		return nil, err
	}
	if cfg.AdminPort, err = envPort("ADMIN_PORT", 7081); err != nil {
		return nil, err
	}
	if cfg.LogLevel, err = envInt("LOG_LEVEL", 4); err != nil {
		return nil, err
	}
	if cfg.PollInterval, err = envPositive("POLL_INTERVAL", time.Minute); err != nil {
		return nil, err
	}
	if cfg.RenewalTimeout, err = envPositive("RENEWAL_TIMEOUT", 2*time.Hour); err != nil {
		return nil, err
	}
	if cfg.CollectionWindow, err = envDuration("COLLECTION_WINDOW", 30*time.Second); err != nil {
		return nil, err
	}
	if cfg.CollectionWindow < 0 {
		return nil, fmt.Errorf("%sCOLLECTION_WINDOW must not be negative", envPrefix)
	}
	if cfg.MinWatchExpiry, err = envDuration("MIN_WATCH_EXPIRY", 24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.MinWatchExpiry < 0 {
		return nil, fmt.Errorf("%sMIN_WATCH_EXPIRY must not be negative", envPrefix)
	}
	if cfg.MaxOnchainFeeRate, err = envFloat("MAX_ONCHAIN_FEE_RATE", 50); err != nil {
		return nil, err
	}
	if cfg.MaxOnchainFeeRate < 1 {
		return nil, fmt.Errorf("%sMAX_ONCHAIN_FEE_RATE must be at least 1", envPrefix)
	}
	if cfg.MaxDelegations, err = envPositive("MAX_DELEGATIONS", 50_000); err != nil {
		return nil, err
	}
	if cfg.MaxTemplates, err = envPositive("MAX_TEMPLATES", 1000); err != nil {
		return nil, err
	}
	if cfg.MaxArtifacts, err = envPositive("MAX_ARTIFACTS", 1000); err != nil {
		return nil, err
	}
	if cfg.MaxDocumentBytes, err = envPositive("MAX_DOCUMENT_BYTES", 65536); err != nil {
		return nil, err
	}
	if cfg.TemplateMaxFailures, err = envPositive("TEMPLATE_MAX_FAILURES", 10); err != nil {
		return nil, err
	}
	if cfg.PublicRateLimit, err = envFloat("PUBLIC_RATE_LIMIT", 5); err != nil {
		return nil, err
	}
	if cfg.DelegateKeys, err = loadDelegateKeys(); err != nil {
		return nil, err
	}
	if cfg.EncryptionKeys, err = loadEncryptionKeys(); err != nil {
		return nil, err
	}
	if cfg.OnchainPollInterval, err = envPositive("ONCHAIN_POLL_INTERVAL", 30*time.Second); err != nil {
		return nil, err
	}
	if cfg.DefaultTemplates, err = envBool("DEFAULT_TEMPLATES", true); err != nil {
		return nil, err
	}
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
		if cfg.AdminUsers, err = LoadAdminUsers(usersFile); err != nil {
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

func (c *Config) AppService(ctx context.Context) (_ application.Service, err error) {
	// the caller may retry: don't leak a pool per attempt
	var closers []func()
	defer func() {
		if err != nil {
			for _, f := range closers {
				f()
			}
		}
	}()
	repo, err := postgres.NewRepository(ctx, c.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	closers = append(closers, func() { _ = repo.Close() })
	// one instance per delegate key: two would race caps and batches
	if err := repo.LockKey(ctx, hex.EncodeToString(c.DelegateKeys[0].PubKey().SerializeCompressed())); err != nil {
		return nil, err
	}
	arkURL := strings.TrimSuffix(c.ArkURL, "/")
	ark, err := client.NewClient(arkURL, "delegateed")
	if err != nil {
		return nil, fmt.Errorf("connect to arkd: %w", err)
	}
	closers = append(closers, ark.Close)
	indexerSvc, err := indexer.NewClient(arkURL)
	if err != nil {
		return nil, fmt.Errorf("connect to indexer: %w", err)
	}
	closers = append(closers, indexerSvc.Close)
	emuURL, creds := grpcTarget(c.EmulatorURL)
	emuConn, err := grpc.NewClient(emuURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connect to emulator: %w", err)
	}
	closers = append(closers, func() { _ = emuConn.Close() })
	info, err := ark.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("arkd info: %w", err)
	}
	explorerSvc, err := explorer.New(c.ExplorerURL, clientlib.NetworkFromString(info.Network))
	if err != nil {
		return nil, fmt.Errorf("configure explorer: %w", err)
	}
	svc, err := application.NewServiceWithKeys(
		ctx, repo, ark, indexerSvc, emulatorclient.NewGRPCClient(emuConn), explorerSvc, c.OnchainPollInterval, c.MaxOnchainFeeRate, c.EncryptionKeys,
		c.DelegateKeys, c.PollInterval, c.RenewalTimeout, c.CollectionWindow,
		application.Limits{
			MinWatchExpiry: c.MinWatchExpiry, MaxDelegations: c.MaxDelegations, MaxTemplates: c.MaxTemplates, MaxArtifacts: c.MaxArtifacts,
			MaxDocumentBytes: c.MaxDocumentBytes, TemplateMaxFailures: c.TemplateMaxFailures,
		},
	)
	if err != nil {
		return nil, err
	}
	if err := c.registerDefaults(ctx, svc); err != nil {
		svc.Stop()
		return nil, fmt.Errorf("default templates: %w", err)
	}
	if err := svc.Bootstrap(ctx); err != nil {
		svc.Stop()
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	go func() {
		// an instance that lost its key's lock would run beside the one that took it
		if err := repo.WatchLock(context.Background(), lockCheckInterval); err != nil {
			log.WithError(err).Fatal("lost the delegate key lock")
		}
	}()
	return svc, nil
}

// registerDefaults trusts only the templates it adds: an operator's later choice survives restarts.
// Only an invalid document fails: the defaults are the daemon's own.
func (c *Config) registerDefaults(ctx context.Context, svc application.Service) error {
	if !c.DefaultTemplates {
		return nil
	}
	for name, doc := range templates.Artifacts {
		if _, err := svc.RegisterArtifact(ctx, doc); err != nil {
			if errors.Is(err, application.ErrInvalidDocument) {
				return err
			}
			// the templates need their artifacts
			log.WithError(err).Error("register default artifact " + name)
			return nil
		}
	}
	stored, err := svc.ListTemplates(ctx, "")
	if err != nil {
		log.WithError(err).Error("list templates")
		return nil
	}
	for name, doc := range templates.Templates {
		t, err := svc.RegisterTemplate(ctx, doc)
		if errors.Is(err, application.ErrInvalidDocument) {
			return err
		}
		if err != nil {
			log.WithError(err).Error("register default template " + name)
			continue
		}
		if slices.ContainsFunc(stored, func(s domain.Template) bool { return s.ID == t.ID }) {
			continue
		}
		if err := svc.SetTemplateTrusted(ctx, t.ID, true); err != nil {
			log.WithError(err).Error("trust default template " + name)
		}
	}
	return nil
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

func loadDelegateKeys() ([]*btcec.PrivateKey, error) {
	if os.Getenv(envPrefix+"DELEGATE_KEYS_FILE") != "" {
		if os.Getenv(envPrefix+"DELEGATE_KEY") != "" || os.Getenv(envPrefix+"DELEGATE_KEY_FILE") != "" || os.Getenv(envPrefix+"PREVIOUS_DELEGATE_KEYS") != "" {
			return nil, fmt.Errorf("%sDELEGATE_KEYS_FILE cannot be combined with individual delegate key settings", envPrefix)
		}
		return readKeyring("DELEGATE_KEYS_FILE")
	}
	active, err := loadDelegateKey()
	if err != nil {
		return nil, err
	}
	keys := []*btcec.PrivateKey{active}
	for _, value := range strings.Split(os.Getenv(envPrefix+"PREVIOUS_DELEGATE_KEYS"), ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key, err := parseDelegateKey("PREVIOUS_DELEGATE_KEYS", value)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return validateDelegateKeys("PREVIOUS_DELEGATE_KEYS", keys)
}

func loadDelegateKey() (*btcec.PrivateKey, error) {
	keyHex := os.Getenv(envPrefix + "DELEGATE_KEY")
	if path := os.Getenv(envPrefix + "DELEGATE_KEY_FILE"); path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%sDELEGATE_KEY_FILE: %w", envPrefix, err)
		}
		return parseDelegateKey("DELEGATE_KEY_FILE", string(content))
	}
	return parseDelegateKey("DELEGATE_KEY", keyHex)
}

func loadEncryptionKeys() ([]*btcec.PrivateKey, error) {
	value := os.Getenv(envPrefix + "ENCRYPTION_KEY")
	path := os.Getenv(envPrefix + "ENCRYPTION_KEYS_FILE")
	switch {
	case value != "" && path != "":
		return nil, fmt.Errorf("%sENCRYPTION_KEY cannot be combined with ENCRYPTION_KEYS_FILE", envPrefix)
	case path != "":
		return readKeyring("ENCRYPTION_KEYS_FILE")
	case value == "":
		return nil, nil
	case strings.ContainsAny(value, "\r\n"):
		return nil, fmt.Errorf("%sENCRYPTION_KEY must contain one key", envPrefix)
	}
	key, err := parseDelegateKey("ENCRYPTION_KEY", value)
	if err != nil {
		return nil, err
	}
	return []*btcec.PrivateKey{key}, nil
}

// readKeyring skips blanks and # comments.
func readKeyring(env string) ([]*btcec.PrivateKey, error) {
	content, err := os.ReadFile(os.Getenv(envPrefix + env))
	if err != nil {
		return nil, fmt.Errorf("%s%s: %w", envPrefix, env, err)
	}
	var keys []*btcec.PrivateKey
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, err := parseDelegateKey(env, line)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return validateDelegateKeys(env, keys)
}

func parseDelegateKey(env, keyHex string) (*btcec.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s%s must be 32 bytes hex", envPrefix, env)
	}
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(raw) || scalar.IsZero() {
		return nil, fmt.Errorf("%s%s must be a valid scalar", envPrefix, env)
	}
	return btcec.PrivKeyFromScalar(&scalar), nil
}

func validateDelegateKeys(env string, keys []*btcec.PrivateKey) ([]*btcec.PrivateKey, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s%s must contain at least one key", envPrefix, env)
	}
	if len(keys) > maxDelegateKeys {
		return nil, fmt.Errorf("%s%s must contain at most %d keys", envPrefix, env, maxDelegateKeys)
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		pub := hex.EncodeToString(key.PubKey().SerializeCompressed())
		if _, ok := seen[pub]; ok {
			return nil, fmt.Errorf("%s%s contains a duplicate key", envPrefix, env)
		}
		seen[pub] = struct{}{}
	}
	return keys, nil
}

func LoadAdminUsers(path string) ([]AdminUser, error) {
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

func envPort(key string, def int) (uint32, error) {
	port, err := envInt(key, def)
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s%s must be between 1 and 65535", envPrefix, key)
	}
	return uint32(port), nil
}

func envPositive[T int | time.Duration](key string, def T) (T, error) {
	var v any
	var err error
	switch d := any(def).(type) {
	case int:
		v, err = envInt(key, d)
	case time.Duration:
		v, err = envDuration(key, d)
	}
	if err != nil {
		return 0, err
	}
	if v.(T) <= 0 {
		return 0, fmt.Errorf("%s%s must be positive", envPrefix, key)
	}
	return v.(T), nil
}

func envBool(key string, def bool) (bool, error) {
	s := os.Getenv(envPrefix + key)
	if s == "" {
		return def, nil
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf("%s%s must be true or false", envPrefix, key)
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
