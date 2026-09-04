package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, uint32(7080), cfg.Port)
	require.Equal(t, 5*time.Second, cfg.PollInterval)
	require.NotNil(t, cfg.SecretKey)
}
