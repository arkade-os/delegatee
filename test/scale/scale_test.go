//go:build scale

// Package scale starts the daemon over half a million delegations and measures what the target asks
// for.
package scale

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	"github.com/arkade-os/executor/test/daemon"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const (
	delegations = 500_000
	boardingOf  = 10 // one in this many delegations watches an onchain input
	coinsOf     = 5  // one in this many delegations holds a stored coin
	arrivalsOf  = 20 // one in this many has a vtxo at arkd the stored coins lack
	maxShard    = 1000
	apiWithin   = 10 * time.Second
	memoryLimit = 1 << 30
)

func TestScale(t *testing.T) {
	d := daemon.Start(t, daemon.WithDefaultTemplates)
	d.Stop()
	renewal, boarding := templateIDs(t, d.DB)
	offchain := seed(t, d, renewal, boarding)
	runtime.GC()
	debug.FreeOSMemory()

	reconciled := make(chan struct{}, 1)
	log.AddHook(&reconcileHook{done: reconciled})
	started := time.Now()
	d = d.Restart(t, daemon.WithDefaultTemplates)
	status, err := d.Admin.GetStatus(t.Context(), &executorv1.GetStatusRequest{})
	require.NoError(t, err)
	_, err = d.Client.GetDelegation(
		t.Context(), &executorv1.GetDelegationRequest{Id: delegations / 2},
	)
	require.NoError(t, err)
	toAPI := time.Since(started)
	afterStart := sample()

	select {
	case <-reconciled:
	case <-time.After(20 * time.Minute):
		t.Fatal("reconcile did not finish")
	}
	reconcile := time.Since(started) - toAPI
	time.Sleep(2 * time.Second)
	afterReconcile := sample()

	sizes := slices.Clone(d.Arkd.SubscriptionSizes)
	t.Logf(
		"\n"+
			"active delegations   %d\n"+
			"offchain scripts     %d\n"+
			"time to API          %s\n"+
			"reconcile            %s\n"+
			"memory after start   %s\n"+
			"memory after reconc  %s\n"+
			"subscriptions        %d (largest %d)",
		status.GetActive(),
		offchain,
		toAPI.Round(time.Millisecond),
		reconcile.Round(time.Millisecond),
		afterStart,
		afterReconcile,
		len(sizes),
		slices.Max(sizes),
	)

	require.EqualValues(t, delegations, status.GetActive())
	require.Less(t, toAPI, apiWithin)
	require.Less(t, afterStart.rss, uint64(memoryLimit))
	require.Less(t, afterReconcile.rss, uint64(memoryLimit))
	require.Len(t, sizes, (offchain+maxShard-1)/maxShard)
	require.LessOrEqual(t, slices.Max(sizes), maxShard)
}

// reconcileHook signals the line the daemon logs once its loop has taken in every reconciled
// script.
type reconcileHook struct{ done chan struct{} }

func (reconcileHook) Levels() []log.Level { return []log.Level{log.InfoLevel} }

func (h *reconcileHook) Fire(e *log.Entry) error {
	if e.Message == "reconcile done" {
		select {
		case h.done <- struct{}{}:
		default:
		}
	}
	return nil
}

type memory struct{ sys, heap, rss uint64 }

func (m memory) String() string {
	return fmt.Sprintf(
		"rss %d MB, go sys %d MB, heap in use %d MB", m.rss>>20, m.sys>>20, m.heap>>20,
	)
}

func sample() memory {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		panic(err)
	}
	kb, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		panic(err)
	}
	return memory{sys: ms.Sys, heap: ms.HeapInuse, rss: kb << 10}
}

// templateIDs finds the default renewal and boarding templates among the stored ones.
func templateIDs(t *testing.T, db *sql.DB) (renewal, boarding string) {
	t.Helper()
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT id FROM templates WHERE type = 'intent' AND convert_from(document, 'UTF8') LIKE '%"before_expiry_seconds": "<renewal_window>"%'
		   AND convert_from(document, 'UTF8') NOT LIKE '%DelegatedBoarding%' AND convert_from(document, 'UTF8') LIKE '%"max_fee": "int"%'
		 ORDER BY id LIMIT 1`,
	).Scan(&renewal))
	require.NoError(t, db.QueryRowContext(
		t.Context(),
		`SELECT id FROM templates WHERE convert_from(document, 'UTF8') LIKE '%DelegatedBoarding%' ORDER BY id LIMIT 1`,
	).Scan(&boarding))
	return renewal, boarding
}

// seed stores the delegations and the coins of some of them, and lands those coins at the arkd
// stand-in. It returns how many offchain scripts the delegations watch.
func seed(t *testing.T, d *daemon.Daemon, renewal, boarding string) int {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC()
	tx, err := d.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("delegations",
		"fingerprint", "address", "template_id", "variables", "inputs", "status"))
	require.NoError(t, err)
	var scripts []string
	for i := 1; i <= delegations; i++ {
		onchain := i%boardingOf == 0
		script := hash("script", i)
		tapscripts := fmt.Sprintf(
			`["%s","%s"]`, hash("leaf0", i)+hash("leaf0", -i), hash("leaf1", i)+hash("leaf1", -i),
		)
		inputs := fmt.Sprintf(
			`[{"Name":"funds","Onchain":%t,"Script":"5120%s","Tapscripts":%s,"Locktime":0}]`,
			onchain, script, tapscripts,
		)
		template, variables := renewal, fmt.Sprintf(
			`{"owner":"%s","exit_delay":"%s","renewal_window":"%s","max_fee":"%s"}`, owner(i),
			daemon.ScriptNum(1<<22|1), daemon.ScriptNum(86400), daemon.ScriptNum(1000),
		)
		if onchain {
			template = boarding
			variables = fmt.Sprintf(
				`{"owner":"%s","boarding_exit_delay":"%s","exit_delay":"%s","renewal_window":"%s","max_fee":"%s"}`,
				owner(
					i,
				),
				daemon.ScriptNum(1<<22|2),
				daemon.ScriptNum(1<<22|1),
				daemon.ScriptNum(86400),
				daemon.ScriptNum(1000),
			)
		} else {
			scripts = append(scripts, "5120"+script)
		}
		_, err := stmt.ExecContext(
			ctx, hash("fingerprint", i), "tark1"+script, template, variables, inputs, "active",
		)
		require.NoError(t, err)
	}
	_, err = stmt.ExecContext(ctx)
	require.NoError(t, err)
	require.NoError(t, stmt.Close())
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO claims (delegation_id, input, script, onchain, locktime)
		SELECT id, 0, inputs->0->>'Script', (inputs->0->>'Onchain')::boolean, 0 FROM delegations`,
	)
	require.NoError(t, err)

	stmt, err = tx.PrepareContext(ctx, pq.CopyIn(
		"coins", "outpoint", "delegation_id", "input", "script", "amount", "expiry", "created_at",
		"due", "status", "onchain",
	))
	require.NoError(t, err)
	week := int64(7 * 24 * 3600)
	var held, arrivals int
	for i := 1; i <= delegations; i++ {
		if i%boardingOf == 0 {
			continue
		}
		if i%arrivalsOf == 2 {
			d.Arkd.Land(
				"5120"+hash("script", i), hash("arrival", i)+":0", 10_000, now.Add(30*24*time.Hour),
			)
			arrivals++
		}
		if i%coinsOf != 1 {
			continue
		}
		outpoint := hash("coin", i) + ":0"
		script := "5120" + hash("script", i)
		due := now.Add(time.Duration(int64(i)*week/delegations) * time.Second)
		expiry := due.Add(24 * time.Hour)
		_, err := stmt.ExecContext(
			ctx, outpoint, i, 0, script, 10_000, expiry, now.Add(-time.Hour), due, "present", false,
		)
		require.NoError(t, err)
		d.Arkd.Land(script, outpoint, 10_000, expiry)
		held++
	}
	_, err = stmt.ExecContext(ctx)
	require.NoError(t, err)
	require.NoError(t, stmt.Close())
	require.NoError(t, tx.Commit())
	_, err = d.DB.ExecContext(context.Background(), "ANALYZE")
	require.NoError(t, err)
	t.Logf("seeded %d delegations, %d stored coins, %d vtxos to find", delegations, held, arrivals)
	return len(scripts)
}

func hash(kind string, n int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d", kind, n))
	return hex.EncodeToString(sum[:])
}

// owner is one of a thousand valid keys.
func owner(n int) string {
	var s btcec.ModNScalar
	s.SetInt(uint32(n%1000 + 1))
	return hex.EncodeToString(btcec.PrivKeyFromScalar(&s).PubKey().SerializeCompressed())
}
