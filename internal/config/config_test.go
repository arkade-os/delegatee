package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestLoad(t *testing.T) {
	_, err := LoadConfig()
	require.Error(t, err, "missing required vars")

	t.Setenv("DELEGATEE_ARK_URL", "localhost:7070")
	t.Setenv("DELEGATEE_EMULATOR_URL", "localhost:7073")
	t.Setenv("DELEGATEE_DATABASE_URL", "postgres://x")
	t.Setenv("DELEGATEE_SECRET_KEY", "00")
	_, err = LoadConfig()
	require.Error(t, err, "short key")

	t.Setenv("DELEGATEE_SECRET_KEY", "0101010101010101010101010101010101010101010101010101010101010101")
	t.Setenv("DELEGATEE_POLL_INTERVAL", "5s")
	t.Setenv("DELEGATEE_ADMIN_AUTH", "file")
	t.Setenv("DELEGATEE_ADMIN_USERS_FILE", adminUsersFile(t))
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, uint32(7080), cfg.Port)
	require.Equal(t, 5*time.Second, cfg.PollInterval)
	require.NotNil(t, cfg.SecretKey)
	require.Len(t, cfg.SecretKeys, 1)
	require.Len(t, cfg.AdminUsers, 1)

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
		"DELEGATEE_DATABASE_URL":     "postgres://x",
		"DELEGATEE_SECRET_KEY":       "0101010101010101010101010101010101010101010101010101010101010101",
		"DELEGATEE_ADMIN_AUTH":       "file",
		"DELEGATEE_ADMIN_USERS_FILE": adminUsersFile(t),
	}
	for name, bad := range map[string]string{
		"DELEGATEE_PORT": "http", "DELEGATEE_ADMIN_PORT": "x", "DELEGATEE_LOG_LEVEL": "debug",
		"DELEGATEE_POLL_INTERVAL": "10", "DELEGATEE_RENEWAL_TIMEOUT": "soon",
		"DELEGATEE_MAX_VTXOS_PER_INTENT": "many", "DELEGATEE_MAX_DELEGATIONS": "1e3",
		"DELEGATEE_SECRET_KEY": "0000000000000000000000000000000000000000000000000000000000000000",
		"DELEGATEE_ARK_URL":    "", "DELEGATEE_EMULATOR_URL": "", "DELEGATEE_DATABASE_URL": "",
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
		"DELEGATEE_POLL_INTERVAL": "0s", "DELEGATEE_RENEWAL_TIMEOUT": "-1s",
		"DELEGATEE_MAX_VTXOS_PER_INTENT": "17", "DELEGATEE_MAX_DELEGATIONS": "0",
		"DELEGATEE_PUBLIC_RATE_LIMIT": "NaN",
		"DELEGATEE_ADMIN_AUTH":        "maybe",
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
	t.Setenv("DELEGATEE_SECRET_KEY_FILE", keyFile)
	t.Setenv("DELEGATEE_MAX_DELEGATIONS", "12")
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.AdminUsers, 1)
	require.Equal(t, 2.5, cfg.PublicRateLimit)
	require.Equal(t, "0202020202020202020202020202020202020202020202020202020202020202", hex.EncodeToString(cfg.SecretKey.Serialize()))
	require.Len(t, cfg.SecretKeys, 1)
	t.Setenv("DELEGATEE_SECRET_KEY_FILE", keyFile+".missing")
	_, err = LoadConfig()
	require.ErrorContains(t, err, "SECRET_KEY_FILE")
	t.Setenv("DELEGATEE_SECRET_KEY_FILE", "")
	require.Equal(t, 12, cfg.MaxDelegations)
	require.Equal(t, uint32(7081), cfg.AdminPort)
	require.Equal(t, 2*time.Hour, cfg.RenewalTimeout)
	require.Equal(t, 16, cfg.MaxVtxosPerIntent)

	// nothing listens there: wiring fails cleanly instead of hanging or leaking
	cfg.DatabaseURL = "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"
	_, err = cfg.AppService(t.Context())
	require.ErrorContains(t, err, "open database")
}

func TestLoadSecretKeyring(t *testing.T) {
	t.Setenv("DELEGATEE_ARK_URL", "localhost:7070")
	t.Setenv("DELEGATEE_EMULATOR_URL", "localhost:7073")
	t.Setenv("DELEGATEE_DATABASE_URL", "postgres://x")
	t.Setenv("DELEGATEE_SECRET_KEY", "")
	t.Setenv("DELEGATEE_SECRET_KEY_FILE", "")
	t.Setenv("DELEGATEE_PREVIOUS_SECRET_KEYS", "")
	t.Setenv("DELEGATEE_ADMIN_AUTH", "file")
	t.Setenv("DELEGATEE_ADMIN_USERS_FILE", adminUsersFile(t))
	path := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.WriteFile(path, []byte(
		"0202020202020202020202020202020202020202020202020202020202020202\n"+"0101010101010101010101010101010101010101010101010101010101010101\n",
	), 0o600))
	t.Setenv("DELEGATEE_SECRET_KEYS_FILE", path)
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.SecretKeys, 2)
	require.Equal(t, "0202020202020202020202020202020202020202020202020202020202020202", hex.EncodeToString(cfg.SecretKey.Serialize()))
}

func TestLoadAllowsExternalAdminAuth(t *testing.T) {
	t.Setenv("DELEGATEE_ARK_URL", "localhost:7070")
	t.Setenv("DELEGATEE_EMULATOR_URL", "localhost:7073")
	t.Setenv("DELEGATEE_DATABASE_URL", "postgres://x")
	t.Setenv("DELEGATEE_SECRET_KEY", "0101010101010101010101010101010101010101010101010101010101010101")
	t.Setenv("DELEGATEE_ADMIN_AUTH", "disabled")
	t.Setenv("DELEGATEE_ADMIN_USERS_FILE", "")
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Empty(t, cfg.AdminUsers)
}

func adminUsersFile(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "admin-users")
	require.NoError(t, os.WriteFile(path, []byte("admin:"+string(hash)+"\n"), 0o600))
	return path
}
