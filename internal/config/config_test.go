package config

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestLoad(t *testing.T) {
	_, err := LoadConfig()
	require.Error(t, err, "missing required vars")

	t.Setenv("DELEGATEE_ARK_URL", "localhost:7070")
	t.Setenv("DELEGATEE_EXPLORER_URL", "http://localhost:3000")
	t.Setenv("DELEGATEE_EMULATOR_URL", "localhost:7073")
	t.Setenv("DELEGATEE_DATABASE_URL", "postgres://x")
	t.Setenv("DELEGATEE_DELEGATE_KEY", "00")
	_, err = LoadConfig()
	require.Error(t, err, "short key")

	t.Setenv("DELEGATEE_DELEGATE_KEY", "0101010101010101010101010101010101010101010101010101010101010101")
	t.Setenv("DELEGATEE_POLL_INTERVAL", "5s")
	t.Setenv("DELEGATEE_ADMIN_AUTH", "file")
	t.Setenv("DELEGATEE_ADMIN_USERS_FILE", adminUsersFile(t))
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, uint32(7080), cfg.Port)
	require.Equal(t, 5*time.Second, cfg.PollInterval)
	require.Equal(t, 30*time.Second, cfg.OnchainPollInterval)
	require.Empty(t, cfg.EncryptionKeys)
	require.Equal(t, 30*time.Second, cfg.CollectionWindow)
	require.Equal(t, 24*time.Hour, cfg.MinWatchExpiry)
	t.Setenv("DELEGATEE_MIN_WATCH_EXPIRY", "0")
	disabled, err := LoadConfig()
	require.NoError(t, err)
	require.Zero(t, disabled.MinWatchExpiry)
	for _, window := range []time.Duration{0, 10 * time.Second} {
		t.Setenv("DELEGATEE_COLLECTION_WINDOW", window.String())
		configured, err := LoadConfig()
		require.NoError(t, err)
		require.Equal(t, window, configured.CollectionWindow)
	}
	require.Len(t, cfg.DelegateKeys, 1)
	require.Len(t, cfg.AdminUsers, 1)
	require.True(t, cfg.DefaultTemplates)
	t.Setenv("DELEGATEE_DEFAULT_TEMPLATES", "false")
	without, err := LoadConfig()
	require.NoError(t, err)
	require.False(t, without.DefaultTemplates)

	for url, want := range map[string]string{
		"https://emulator.mutinynet.arkade.sh/": "emulator.mutinynet.arkade.sh:443",
		"http://emulator:7073":                  "emulator:7073",
		"localhost:7073":                        "localhost:7073",
	} {
		target, _ := grpcTarget(url)
		require.Equal(t, want, target)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	base := map[string]string{
		"DELEGATEE_ARK_URL": "localhost:7070", "DELEGATEE_EMULATOR_URL": "localhost:7073",
		"DELEGATEE_EXPLORER_URL":     "http://localhost:3000",
		"DELEGATEE_DATABASE_URL":     "postgres://x",
		"DELEGATEE_DELEGATE_KEY":     "0101010101010101010101010101010101010101010101010101010101010101",
		"DELEGATEE_ADMIN_AUTH":       "file",
		"DELEGATEE_ADMIN_USERS_FILE": adminUsersFile(t),
	}
	for name, bad := range map[string]string{
		"DELEGATEE_PORT": "http", "DELEGATEE_ADMIN_PORT": "x", "DELEGATEE_LOG_LEVEL": "debug",
		"DELEGATEE_COLLECTION_WINDOW":     "soon",
		"DELEGATEE_MIN_WATCH_EXPIRY":      "-1h",
		"DELEGATEE_ONCHAIN_POLL_INTERVAL": "soon",
		"DELEGATEE_POLL_INTERVAL":         "10", "DELEGATEE_RENEWAL_TIMEOUT": "soon",
		"DELEGATEE_MAX_DELEGATIONS":      "1e3",
		"DELEGATEE_MAX_ONCHAIN_FEE_RATE": "fast",
		"DELEGATEE_DEFAULT_TEMPLATES":    "maybe",
		"DELEGATEE_DELEGATE_KEY":         "0000000000000000000000000000000000000000000000000000000000000000",
		"DELEGATEE_ARK_URL":              "", "DELEGATEE_EMULATOR_URL": "", "DELEGATEE_DATABASE_URL": "",
		"DELEGATEE_EXPLORER_URL": "",
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			t.Setenv(name, bad)
			_, err := LoadConfig()
			require.ErrorContains(t, err, name)
		})
	}
	for name, bad := range map[string]string{
		"DELEGATEE_PORT": "0", "DELEGATEE_ADMIN_PORT": "65536",
		"DELEGATEE_COLLECTION_WINDOW":     "-1s",
		"DELEGATEE_ONCHAIN_POLL_INTERVAL": "0s",
		"DELEGATEE_POLL_INTERVAL":         "0s", "DELEGATEE_RENEWAL_TIMEOUT": "-1s",
		"DELEGATEE_MAX_DELEGATIONS":   "0",
		"DELEGATEE_PUBLIC_RATE_LIMIT": "NaN", "DELEGATEE_MAX_ONCHAIN_FEE_RATE": "0.5",
		"DELEGATEE_ADMIN_AUTH": "maybe",
	} {
		t.Run(name+" semantic", func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			t.Setenv(name, bad)
			_, err := LoadConfig()
			require.ErrorContains(t, err, name)
		})
	}

	for k, v := range base {
		t.Setenv(k, v)
	}
	t.Setenv("DELEGATEE_PUBLIC_RATE_LIMIT", "-1")
	_, err := LoadConfig()
	require.ErrorContains(t, err, "PUBLIC_RATE_LIMIT")
	t.Setenv("DELEGATEE_PUBLIC_RATE_LIMIT", "2.5")

	// a key file wins over the variable, and must exist
	keyFile := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(keyFile, []byte("0202020202020202020202020202020202020202020202020202020202020202\n"), 0o600))
	t.Setenv("DELEGATEE_DELEGATE_KEY_FILE", keyFile)
	t.Setenv("DELEGATEE_MAX_DELEGATIONS", "12")
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.AdminUsers, 1)
	require.Equal(t, 2.5, cfg.PublicRateLimit)
	require.Equal(t, "0202020202020202020202020202020202020202020202020202020202020202", hex.EncodeToString(cfg.DelegateKeys[0].Serialize()))
	require.Len(t, cfg.DelegateKeys, 1)
	t.Setenv("DELEGATEE_DELEGATE_KEY_FILE", keyFile+".missing")
	_, err = LoadConfig()
	require.ErrorContains(t, err, "DELEGATE_KEY_FILE")
	t.Setenv("DELEGATEE_DELEGATE_KEY_FILE", "")
	require.Equal(t, 12, cfg.MaxDelegations)
	require.Equal(t, uint32(7081), cfg.AdminPort)
	require.Equal(t, 2*time.Hour, cfg.RenewalTimeout)
	require.Equal(t, 50.0, cfg.MaxOnchainFeeRate)

	// nothing listens there: wiring fails cleanly instead of hanging or leaking
	cfg.DatabaseURL = "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"
	_, err = cfg.AppService(t.Context())
	require.ErrorContains(t, err, "open database")
}

func TestLoadDelegateKeyring(t *testing.T) {
	t.Setenv("DELEGATEE_ARK_URL", "localhost:7070")
	t.Setenv("DELEGATEE_EXPLORER_URL", "http://localhost:3000")
	t.Setenv("DELEGATEE_EMULATOR_URL", "localhost:7073")
	t.Setenv("DELEGATEE_DATABASE_URL", "postgres://x")
	t.Setenv("DELEGATEE_DELEGATE_KEY", "")
	t.Setenv("DELEGATEE_DELEGATE_KEY_FILE", "")
	t.Setenv("DELEGATEE_PREVIOUS_DELEGATE_KEYS", "")
	t.Setenv("DELEGATEE_ADMIN_AUTH", "file")
	t.Setenv("DELEGATEE_ADMIN_USERS_FILE", adminUsersFile(t))
	path := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.WriteFile(path, []byte(
		"0202020202020202020202020202020202020202020202020202020202020202\n"+"0101010101010101010101010101010101010101010101010101010101010101\n",
	), 0o600))
	t.Setenv("DELEGATEE_DELEGATE_KEYS_FILE", path)
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.DelegateKeys, 2)
	require.Equal(t, "0202020202020202020202020202020202020202020202020202020202020202", hex.EncodeToString(cfg.DelegateKeys[0].Serialize()))
}

func TestLoadAllowsExternalAdminAuth(t *testing.T) {
	t.Setenv("DELEGATEE_ARK_URL", "localhost:7070")
	t.Setenv("DELEGATEE_EXPLORER_URL", "http://localhost:3000")
	t.Setenv("DELEGATEE_EMULATOR_URL", "localhost:7073")
	t.Setenv("DELEGATEE_DATABASE_URL", "postgres://x")
	t.Setenv("DELEGATEE_DELEGATE_KEY", "0101010101010101010101010101010101010101010101010101010101010101")
	t.Setenv("DELEGATEE_ADMIN_AUTH", "disabled")
	t.Setenv("DELEGATEE_ADMIN_USERS_FILE", "")
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Empty(t, cfg.AdminUsers)
}

func TestEncryptionKeyConfiguration(t *testing.T) {
	active := strings.Repeat("01", 32)
	previous := strings.Repeat("02", 32)
	for _, tc := range []struct {
		name, key, file string
		useFile         bool
		want            string
		count           int
		bad             bool
	}{
		{name: "optional"},
		{name: "single", key: active, count: 1},
		{name: "retained", file: "# active first\n" + active + "\n\n" + previous + "\n", useFile: true, count: 2},
		{name: "conflict", key: active, file: previous, useFile: true, bad: true},
		{name: "empty file", useFile: true, bad: true, want: "DELEGATEE_ENCRYPTION_KEYS_FILE must contain at least one key"},
		{name: "duplicate", file: active + "\n" + active, useFile: true, bad: true, want: "DELEGATEE_ENCRYPTION_KEYS_FILE contains a duplicate key"},
		{name: "short", key: "01", bad: true},
		{name: "zero", key: strings.Repeat("00", 32), bad: true},
		{name: "overflow", key: strings.Repeat("ff", 32), bad: true},
		{name: "malformed", key: strings.Repeat("zz", 32), bad: true},
		{name: "single cannot be list", key: active + "\n" + previous, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DELEGATEE_ENCRYPTION_KEY", tc.key)
			t.Setenv("DELEGATEE_ENCRYPTION_KEYS_FILE", "")
			if tc.useFile {
				path := filepath.Join(t.TempDir(), "secrets")
				require.NoError(t, os.WriteFile(path, []byte(tc.file), 0600))
				t.Setenv("DELEGATEE_ENCRYPTION_KEYS_FILE", path)
			}
			keys, err := loadEncryptionKeys()
			if tc.bad {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.want)
				return
			}
			require.NoError(t, err)
			require.Len(t, keys, tc.count)
			if tc.count > 0 {
				require.Equal(t, active, hex.EncodeToString(keys[0].Serialize()))
			}
			if tc.count > 1 {
				require.Equal(t, previous, hex.EncodeToString(keys[1].Serialize()))
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		t.Setenv("DELEGATEE_ENCRYPTION_KEY", "")
		t.Setenv("DELEGATEE_ENCRYPTION_KEYS_FILE", filepath.Join(t.TempDir(), "missing"))
		_, err := loadEncryptionKeys()
		require.ErrorContains(t, err, "ENCRYPTION_KEYS_FILE")
	})
}

func TestRegisterDefaults(t *testing.T) {
	renewal, boarding := "d901cb8554a77524fb55ebfcde8e1c468871de45163abf34e988c47f1fa36896", "02b4e8bdfb52d7450ab75510cfaff36da5b88323291325e38358df10684a8344"
	claim, refund := "c6e10a94e6b27b1c29dc3c9eae95d1f01ef9e4142f882f9ce9888a416d7ae01d", "978df861b2ae33f1373fd9ead844b074b3575d2341e98f1d50114179a9ed7d6d"
	on := &Config{DefaultTemplates: true}
	svc := newDefaultsService()
	require.NoError(t, on.registerDefaults(t.Context(), svc))
	require.Len(t, svc.artifacts, 1)
	require.Equal(t, map[string]bool{renewal: true, boarding: true, claim: true, refund: true}, svc.trusted())

	require.NoError(t, svc.SetTemplateTrusted(t.Context(), boarding, false))
	trusts := svc.trusts
	require.NoError(t, on.registerDefaults(t.Context(), svc))
	require.Equal(t, trusts, svc.trusts, "a restart changes nothing")
	require.Equal(t, map[string]bool{renewal: true, boarding: false, claim: true, refund: true}, svc.trusted(), "an untrusted default stays untrusted")

	off := newDefaultsService()
	require.NoError(t, (&Config{}).registerDefaults(t.Context(), off))
	require.Empty(t, off.artifacts)
	require.Empty(t, off.templates)

	failing := newDefaultsService()
	failing.err = errors.New("database down")
	require.NoError(t, on.registerDefaults(t.Context(), failing), "a failure to register does not stop startup")
	failing.err = fmt.Errorf("%w: bad", application.ErrInvalidDocument)
	require.ErrorIs(t, on.registerDefaults(t.Context(), failing), application.ErrInvalidDocument)
}

func adminUsersFile(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "admin-users")
	require.NoError(t, os.WriteFile(path, []byte("admin:"+string(hash)+"\n"), 0o600))
	return path
}

// defaultsService registers documents like the service: an existing id is returned as is.
type defaultsService struct {
	application.Service
	artifacts map[string][]byte
	templates map[string]*domain.Template
	trusts    int
	err       error
}

func newDefaultsService() *defaultsService {
	return &defaultsService{artifacts: map[string][]byte{}, templates: map[string]*domain.Template{}}
}

func (s *defaultsService) RegisterArtifact(_ context.Context, doc []byte) (*domain.Artifact, error) {
	if s.err != nil {
		return nil, s.err
	}
	a, err := template.ParseArtifact(doc)
	if err != nil {
		return nil, err
	}
	s.artifacts[a.ID] = doc
	return &domain.Artifact{ID: a.ID, Document: doc}, nil
}

func (s *defaultsService) RegisterTemplate(ctx context.Context, doc []byte) (*domain.Template, error) {
	parsed, err := template.Parse(ctx, doc, func(_ context.Context, id string) ([]byte, error) { return s.artifacts[id], nil })
	if err != nil {
		return nil, err
	}
	if t, ok := s.templates[parsed.ID()]; ok {
		return t, nil
	}
	s.templates[parsed.ID()] = &domain.Template{ID: parsed.ID(), Document: doc}
	return s.templates[parsed.ID()], nil
}

func (s *defaultsService) ListTemplates(context.Context, string) ([]domain.Template, error) {
	var out []domain.Template
	for _, t := range s.templates {
		out = append(out, *t)
	}
	return out, nil
}

func (s *defaultsService) SetTemplateTrusted(_ context.Context, id string, trusted bool) error {
	s.templates[id].Trusted = trusted
	s.trusts++
	return nil
}

func (s *defaultsService) trusted() map[string]bool {
	out := map[string]bool{}
	for id, t := range s.templates {
		out[id] = t.Trusted
	}
	return out
}
