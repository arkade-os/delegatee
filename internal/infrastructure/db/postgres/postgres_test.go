package postgres

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestDelegationLifecycle(t *testing.T) {
	repo := testRepo(t)
	ctx := t.Context()
	require.NoError(t, repo.Ping(ctx))
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	address := "tark1test" + suffix
	tmpl, err := repo.CreateTemplate(ctx, domain.Template{ID: "template" + suffix, Document: []byte(`{}`)}, 0)
	require.NoError(t, err)
	slots := []domain.SlotBinding{{Name: "funds", Tapscripts: []string{"aa", "bb"}, Script: "5120cc"}}
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	newWatch := func() domain.Delegation {
		return domain.Delegation{
			Fingerprint: "fp" + suffix, Address: address, TemplateID: tmpl.ID, Variables: map[string]string{"owner": "02aa"},
			ExpiresAt: &expiresAt, DelegatePubKey: "02bb", Slots: slots,
		}
	}

	other := newWatch()
	other.Fingerprint, other.Address = "other"+suffix, "tark1other"+suffix
	_, err = repo.Create(ctx, other, 0)
	require.NoError(t, err)
	before, err := repo.CountActive(ctx)
	require.NoError(t, err)
	_, err = repo.Create(ctx, newWatch(), int(before))
	require.ErrorIs(t, err, domain.ErrCapReached)
	d, err := repo.Create(ctx, newWatch(), int(before)+1)
	require.NoError(t, err)
	require.Equal(t, slots, d.Slots, "slots round-trip")
	require.Equal(t, map[string]string{"owner": "02aa"}, d.Variables)
	require.Zero(t, d.ParentID)
	require.Equal(t, "fp"+suffix, d.Fingerprint)
	require.NotNil(t, d.ExpiresAt)
	require.True(t, expiresAt.Equal(*d.ExpiresAt))
	require.Equal(t, domain.DelegationStatusActive, d.Status)
	after, err := repo.CountActive(ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, after)

	// the fingerprint is unique among active rows: the stored one is returned, even at the cap
	same, err := repo.Create(ctx, newWatch(), int(before))
	require.NoError(t, err)
	require.Equal(t, d, same)
	after, err = repo.CountActive(ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, after)

	got, err := repo.Get(ctx, address)
	require.NoError(t, err)
	require.Equal(t, d.ID, got.ID)
	byID, err := repo.GetByID(ctx, d.ID)
	require.NoError(t, err)
	require.Equal(t, slots, byID.Slots)
	_, err = repo.GetByID(ctx, -1)
	require.ErrorIs(t, err, domain.ErrDelegationNotFound)
	_, err = repo.Get(ctx, address+"nope")
	require.ErrorIs(t, err, domain.ErrDelegationNotFound)
	_, err = repo.Get(ctx, "")
	require.ErrorIs(t, err, domain.ErrDelegationNotFound)

	require.NoError(t, repo.SetStatus(ctx, d.ID, domain.DelegationStatusCancelled))
	stopped, err := repo.Get(ctx, address)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusCancelled, stopped.Status)
	active, err := repo.List(ctx, domain.DelegationStatusActive)
	require.NoError(t, err)
	for _, a := range active {
		require.NotEqual(t, address, a.Address)
	}

	// after cancel the same fingerprint registers again, as a new row that Get prefers
	again, err := repo.Create(ctx, newWatch(), 0)
	require.NoError(t, err)
	require.NotEqual(t, d.ID, again.ID)
	reread, err := repo.Get(ctx, address)
	require.NoError(t, err)
	require.Equal(t, again.ID, reread.ID)
	require.Equal(t, domain.DelegationStatusActive, reread.Status)

	// an advertisement: no address, no expiry, every slot bound
	bound := []domain.SlotBinding{
		{Name: "counter", Tapscripts: []string{"aa"}, Script: "5120aa", Outpoint: "11:0"},
		{Name: "reserve", Onchain: true, Tapscripts: []string{"bb"}, Script: "5120bb", Outpoint: "22:1"},
	}
	adv, err := repo.Create(ctx, domain.Delegation{
		Fingerprint: "adv" + suffix, TemplateID: tmpl.ID, ParentID: d.ID, DelegatePubKey: "02bb", Slots: bound,
	}, 0)
	require.NoError(t, err)
	require.Empty(t, adv.Address)
	require.Equal(t, d.ID, adv.ParentID)
	require.Nil(t, adv.ExpiresAt)
	require.Equal(t, map[string]string{}, adv.Variables)
	require.Equal(t, bound, adv.Slots)
	byFingerprint, err := repo.GetByFingerprint(ctx, "adv"+suffix)
	require.NoError(t, err)
	require.Equal(t, adv.ID, byFingerprint.ID)
	byOutpoint, err := repo.GetActiveByOutpoint(ctx, "22:1")
	require.NoError(t, err)
	require.Equal(t, adv.ID, byOutpoint.ID, "the second slot counts too")
	_, err = repo.GetActiveByOutpoint(ctx, "22:2")
	require.ErrorIs(t, err, domain.ErrDelegationNotFound)
	require.NoError(t, repo.SetStatus(ctx, adv.ID, domain.DelegationStatusDone))
	done, err := repo.GetByID(ctx, adv.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, done.Status)
	// the newest row is found whatever its status; a stopped row keeps its status
	byFingerprint, err = repo.GetByFingerprint(ctx, "adv"+suffix)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, byFingerprint.Status)
	_, err = repo.GetActiveByOutpoint(ctx, "22:1")
	require.ErrorIs(t, err, domain.ErrDelegationNotFound)
	require.NoError(t, repo.SetStatus(ctx, adv.ID, domain.DelegationStatusCancelled))
	done, err = repo.GetByID(ctx, adv.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, done.Status, "done stays done")
	require.ErrorIs(t, repo.SetStatus(ctx, -1, domain.DelegationStatusDone), domain.ErrDelegationNotFound)

	// Expire flips active watches whose expiry passed, and nothing else
	_, err = repo.Expire(ctx, expiresAt.Add(-time.Minute))
	require.NoError(t, err)
	got, err = repo.GetByID(ctx, again.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusActive, got.Status, "not yet expired")
	n, err := repo.Expire(ctx, expiresAt.Add(time.Minute))
	require.NoError(t, err)
	require.Positive(t, n)
	got, err = repo.GetByID(ctx, again.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusExpired, got.Status)
	stopped, err = repo.GetByID(ctx, d.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusCancelled, stopped.Status, "a cancelled row stays cancelled")
	got, err = repo.GetByID(ctx, adv.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusDone, got.Status, "not a watch")
}

func TestRenewalHistory(t *testing.T) {
	repo := testRepo(t)
	ctx := t.Context()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tmpl, err := repo.CreateTemplate(ctx, domain.Template{ID: "template" + suffix, Document: []byte(`{}`)}, 0)
	require.NoError(t, err)
	d, err := repo.Create(ctx, domain.Delegation{
		Address: "tark1hist" + suffix, TemplateID: tmpl.ID, Fingerprint: "hist" + suffix,
		DelegatePubKey: "02bb", Slots: []domain.SlotBinding{{Name: "funds", Tapscripts: []string{"aa"}}},
	}, 0)
	require.NoError(t, err)
	lonely, err := repo.Create(ctx, domain.Delegation{
		Address: "tark1lone" + suffix, TemplateID: tmpl.ID, Fingerprint: "lone" + suffix,
		DelegatePubKey: "02bb", Slots: []domain.SlotBinding{{Name: "funds", Tapscripts: []string{"aa"}}},
	}, 0)
	require.NoError(t, err)

	for _, ren := range []domain.Renewal{
		{DelegationID: d.ID, Outpoints: []string{"a:0"}, Error: "old failure"},
		{DelegationID: d.ID, Outpoints: []string{"a:0", "b:1"}, CommitmentTxid: "cc", Success: true},
		{DelegationID: lonely.ID, Outpoints: []string{"z:0"}, Error: "still failing"},
	} {
		require.NoError(t, repo.RecordRenewal(ctx, ren))
	}
	// age the first of d and the only one of lonely
	_, err = repo.db.ExecContext(ctx, `UPDATE renewals SET attempted_at = NOW() - INTERVAL '90 days'
		WHERE (delegation_id = $1 AND error = 'old failure') OR delegation_id = $2`, d.ID, lonely.ID)
	require.NoError(t, err)

	history, err := repo.ListRenewals(ctx, d.ID, 10)
	require.NoError(t, err)
	require.Len(t, history, 2)
	require.True(t, history[0].Success, "newest first")
	require.Equal(t, []string{"a:0", "b:1"}, history[0].Outpoints)
	limited, err := repo.ListRenewals(ctx, d.ID, 1)
	require.NoError(t, err)
	require.Len(t, limited, 1)

	last, err := repo.LastRenewals(ctx)
	require.NoError(t, err)
	require.Equal(t, "cc", last[d.ID].CommitmentTxid)
	require.Equal(t, "still failing", last[lonely.ID].Error)

	// pruning drops old history but never a delegation's latest state
	require.NoError(t, repo.PruneRenewals(ctx, time.Now().Add(-30*24*time.Hour)))
	history, err = repo.ListRenewals(ctx, d.ID, 10)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.True(t, history[0].Success)
	kept, err := repo.ListRenewals(ctx, lonely.ID, 10)
	require.NoError(t, err)
	require.Len(t, kept, 1, "a failure stored once must survive while it is the latest")
}

func TestTemplatesAndArtifacts(t *testing.T) {
	repo := testRepo(t)
	ctx := t.Context()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	artifactID, templateID := "artifact"+suffix, "template"+suffix

	_, err := repo.CreateArtifact(ctx, "other"+artifactID, []byte(`{"b":1}`), 0)
	require.NoError(t, err)
	_, err = repo.CreateTemplate(ctx, domain.Template{ID: "other" + templateID, Document: []byte(`{}`)}, 0)
	require.NoError(t, err)
	var artifacts, templates int
	require.NoError(t, repo.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM artifacts), (SELECT COUNT(*) FROM templates)`).Scan(&artifacts, &templates))
	_, err = repo.CreateArtifact(ctx, artifactID, []byte(`{"a":1}`), artifacts)
	require.ErrorIs(t, err, domain.ErrCapReached)
	a, err := repo.CreateArtifact(ctx, artifactID, []byte(`{"a":1}`), artifacts+1)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"a":1}`), a.Document)
	again, err := repo.CreateArtifact(ctx, artifactID, []byte(`{"a":1, "spaced":true}`), artifacts)
	require.NoError(t, err)
	require.Equal(t, a.Document, again.Document, "first bytes win, even at the cap")
	_, err = repo.GetArtifact(ctx, "nope")
	require.ErrorIs(t, err, domain.ErrArtifactNotFound)

	summaries, err := repo.ListArtifacts(ctx)
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(summaries, func(x domain.Artifact) bool { return x.ID == artifactID && len(x.Document) == 0 }))

	tmpl := domain.Template{
		ID: templateID, Document: []byte(`{"t":1}`), ArtifactIDs: []string{artifactID},
		Params: []domain.Param{{Name: "owner", Type: "pubkey"}},
	}
	_, err = repo.CreateTemplate(ctx, tmpl, templates)
	require.ErrorIs(t, err, domain.ErrCapReached)
	created, err := repo.CreateTemplate(ctx, tmpl, templates+1)
	require.NoError(t, err)
	require.Equal(t, domain.TemplateStatusActive, created.Status)
	require.Equal(t, tmpl.Params, created.Params)
	require.Equal(t, []string{artifactID}, created.ArtifactIDs)
	dup, err := repo.CreateTemplate(ctx, tmpl, templates)
	require.NoError(t, err)
	require.Equal(t, created.CreatedAt, dup.CreatedAt, "the stored one, even at the cap")

	require.ErrorIs(t, repo.DeleteArtifact(ctx, artifactID), domain.ErrArtifactInUse)
	require.ErrorIs(t, repo.DeleteArtifact(ctx, "nope"), domain.ErrArtifactNotFound)

	active, err := repo.ListTemplates(ctx, domain.TemplateStatusActive)
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(active, func(x domain.Template) bool { return x.ID == templateID }))
	require.False(t, slices.ContainsFunc(active, func(x domain.Template) bool { return len(x.Document) > 0 }), "listings leave documents out")
	require.NoError(t, repo.SetTemplateStatus(ctx, templateID, domain.TemplateStatusDisabled))
	require.ErrorIs(t, repo.SetTemplateStatus(ctx, "nope", domain.TemplateStatusDisabled), domain.ErrTemplateNotFound)
	active, err = repo.ListTemplates(ctx, domain.TemplateStatusActive)
	require.NoError(t, err)
	require.False(t, slices.ContainsFunc(active, func(x domain.Template) bool { return x.ID == templateID }))

	// the valve: failures count up, disable at the threshold, reset on success or re-enable
	require.NoError(t, repo.SetTemplateStatus(ctx, templateID, domain.TemplateStatusActive))
	failures, status, err := repo.RecordTemplateOutcome(ctx, templateID, false, 2)
	require.NoError(t, err)
	require.Equal(t, 1, failures)
	require.Equal(t, domain.TemplateStatusActive, status)
	failures, status, err = repo.RecordTemplateOutcome(ctx, templateID, true, 2)
	require.NoError(t, err)
	require.Equal(t, 0, failures)
	for range 2 {
		failures, status, err = repo.RecordTemplateOutcome(ctx, templateID, false, 2)
		require.NoError(t, err)
	}
	require.Equal(t, 2, failures)
	require.Equal(t, domain.TemplateStatusDisabled, status)
	require.NoError(t, repo.SetTemplateStatus(ctx, templateID, domain.TemplateStatusActive))
	got, err := repo.GetTemplate(ctx, templateID)
	require.NoError(t, err)
	require.Equal(t, 0, got.Failures, "re-enabling resets the counter")
	require.False(t, got.Trusted, "untrusted by default")
	require.NoError(t, repo.SetTemplateTrusted(ctx, templateID, true))
	got, err = repo.GetTemplate(ctx, templateID)
	require.NoError(t, err)
	require.True(t, got.Trusted)
	require.ErrorIs(t, repo.SetTemplateTrusted(ctx, "nope", true), domain.ErrTemplateNotFound)

	// a delegation pins its template
	d, err := repo.Create(ctx, domain.Delegation{
		Address: "tark1tmpl" + suffix, TemplateID: templateID, Variables: map[string]string{"owner": "02aa"},
		Fingerprint: "tmpl" + suffix, DelegatePubKey: "02bb",
		Slots: []domain.SlotBinding{{Name: "funds", Tapscripts: []string{"aa"}}},
	}, 0)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"owner": "02aa"}, d.Variables)
	require.Equal(t, templateID, d.TemplateID)
	require.Equal(t, "02bb", d.DelegatePubKey)
	counts, err := repo.CountDelegationsByTemplate(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), counts[templateID])
	require.ErrorIs(t, repo.DeleteTemplate(ctx, templateID), domain.ErrTemplateInUse)
	require.NoError(t, repo.SetStatus(ctx, d.ID, domain.DelegationStatusCancelled))
	require.ErrorIs(t, repo.DeleteTemplate(ctx, templateID), domain.ErrTemplateInUse, "a cancelled delegation still references it")

	// nil Variables/Slots/Params normalize to empty collections, not a stored JSON null
	nilTemplateID := "niltemplate" + suffix
	nilTmpl, err := repo.CreateTemplate(ctx, domain.Template{ID: nilTemplateID, Document: []byte(`{}`)}, 0)
	require.NoError(t, err)
	require.Equal(t, []domain.Param{}, nilTmpl.Params)
	gotNilTmpl, err := repo.GetTemplate(ctx, nilTemplateID)
	require.NoError(t, err)
	require.Equal(t, []domain.Param{}, gotNilTmpl.Params)
	nilD, err := repo.Create(ctx, domain.Delegation{
		Address: "tark1nilargs" + suffix, TemplateID: nilTemplateID, Fingerprint: "nil" + suffix, DelegatePubKey: "02bb",
	}, 0)
	require.NoError(t, err)
	require.Equal(t, map[string]string{}, nilD.Variables)
	require.Equal(t, []domain.SlotBinding{}, nilD.Slots)
	gotNilD, err := repo.Get(ctx, nilD.Address)
	require.NoError(t, err)
	require.Equal(t, map[string]string{}, gotNilD.Variables)
	require.Equal(t, []domain.SlotBinding{}, gotNilD.Slots)
}

func TestSettlements(t *testing.T) {
	repo := testRepo(t)
	ctx := t.Context()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tmpl, err := repo.CreateTemplate(ctx, domain.Template{ID: "template" + suffix, Document: []byte(`{}`)}, 0)
	require.NoError(t, err)
	watch, err := repo.Create(ctx, domain.Delegation{
		Address: "tark1settle" + suffix, TemplateID: tmpl.ID, Fingerprint: "settle" + suffix,
		DelegatePubKey: "02bb", Slots: []domain.SlotBinding{{Name: "funds", Tapscripts: []string{"aa"}}},
	}, 0)
	require.NoError(t, err)
	pending := domain.Settlement{
		Txid: "ark" + suffix, SpentBy: "ark" + suffix, DelegationID: watch.ID, Tx: []byte{1, 2},
		Outpoints: map[int]string{0: "ark:0", 2: "ark:2"}, Sources: [][]byte{{1, 2}, {3}},
		Coins: []string{"coin:0"}, Checkpoints: []string{"u1", "u2"}, Finals: []string{"cp1", "cp2"},
	}
	require.NoError(t, repo.SaveSettlement(ctx, pending))
	batch := pending
	batch.Txid, batch.SpentBy, batch.Finals = "logical"+suffix, "commitment"+suffix, nil
	require.NoError(t, repo.SaveSettlement(ctx, batch))
	pending.Finals, pending.Landed = nil, true
	require.NoError(t, repo.SaveSettlement(ctx, pending), "finalized")

	rows := settlementsOf(t, repo, watch.ID)
	require.Len(t, rows, 2)
	for _, row := range rows {
		require.False(t, row.CreatedAt.IsZero())
		row.CreatedAt = time.Time{}
		require.Empty(t, row.Finals)
		row.Finals = nil
		require.Contains(t, []domain.Settlement{pending, batch}, row)
	}

	require.NoError(t, repo.DeleteSettlement(ctx, batch.Txid, batch.SpentBy))
	require.NoError(t, repo.DeleteSettlement(ctx, batch.Txid, batch.SpentBy), "gone already")
	require.Len(t, settlementsOf(t, repo, watch.ID), 1)
	require.NoError(t, repo.DeleteSettlement(ctx, pending.Txid, pending.SpentBy))
	require.Empty(t, settlementsOf(t, repo, watch.ID))
}

func TestDelegationPages(t *testing.T) {
	repo := testRepo(t)
	ctx := t.Context()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tmpl, err := repo.CreateTemplate(ctx, domain.Template{ID: "page" + suffix, Document: []byte(`{}`)}, 0)
	require.NoError(t, err)
	var ids []int64
	for i := range 3 {
		d, err := repo.Create(ctx, domain.Delegation{
			Fingerprint: fmt.Sprintf("page%d-%s", i, suffix), TemplateID: tmpl.ID, DelegatePubKey: "02bb",
		}, 0)
		require.NoError(t, err)
		ids = append(ids, d.ID)
	}
	require.NoError(t, repo.SetStatus(ctx, ids[1], domain.DelegationStatusCancelled))

	first, err := repo.ListPage(ctx, "", 0, 2)
	require.NoError(t, err)
	require.Len(t, first, 2)
	require.Equal(t, ids[2], first[0].ID, "newest first")
	require.Equal(t, ids[1], first[1].ID)
	next, err := repo.ListPage(ctx, "", first[1].ID, 2)
	require.NoError(t, err)
	require.Equal(t, ids[0], next[0].ID)
	active, err := repo.ListPage(ctx, domain.DelegationStatusActive, ids[2]+1, 2)
	require.NoError(t, err)
	require.Equal(t, []int64{ids[2], ids[0]}, []int64{active[0].ID, active[1].ID})
}

func TestResume(t *testing.T) {
	repo := testRepo(t)
	ctx := t.Context()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tmpl, err := repo.CreateTemplate(ctx, domain.Template{ID: "resume" + suffix, Document: []byte(`{}`)}, 0)
	require.NoError(t, err)
	watch := domain.Delegation{Fingerprint: "resume" + suffix, TemplateID: tmpl.ID, DelegatePubKey: "02bb"}
	d, err := repo.Create(ctx, watch, 0)
	require.NoError(t, err)

	require.ErrorIs(t, repo.Resume(ctx, d.ID), domain.ErrNotCancelled)
	require.ErrorIs(t, repo.Resume(ctx, -1), domain.ErrDelegationNotFound)
	require.NoError(t, repo.SetStatus(ctx, d.ID, domain.DelegationStatusCancelled))
	require.NoError(t, repo.Resume(ctx, d.ID))
	got, err := repo.GetByID(ctx, d.ID)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusActive, got.Status)

	require.NoError(t, repo.SetStatus(ctx, d.ID, domain.DelegationStatusExpired))
	newer, err := repo.Create(ctx, watch, 0)
	require.NoError(t, err)
	latest, err := repo.GetByFingerprint(ctx, watch.Fingerprint)
	require.NoError(t, err)
	require.Equal(t, newer.ID, latest.ID)
}

func TestOneInstancePerKey(t *testing.T) {
	first, second := testRepo(t), testRepo(t)
	key := fmt.Sprintf("02%d", time.Now().UnixNano())
	require.NoError(t, first.LockKey(t.Context(), key))
	require.ErrorIs(t, second.LockKey(t.Context(), key), ErrKeyInUse)
	require.NoError(t, second.LockKey(t.Context(), key+"other"), "another key is free")

	require.NoError(t, first.Close())
	require.NoError(t, testRepo(t).LockKey(t.Context(), key), "released with its connection")
}

func TestLockWatch(t *testing.T) {
	ctx := t.Context()
	first, other := testRepo(t), testRepo(t)
	key := fmt.Sprintf("02watch%d", time.Now().UnixNano())
	require.NoError(t, first.LockKey(ctx, key))
	require.NoError(t, first.CheckLock(ctx))

	// the lock's connection dies and nobody took the key: taken again
	dropLockConn(t, first, other)
	require.NoError(t, first.CheckLock(ctx))
	require.ErrorIs(t, other.LockKey(ctx, key), ErrKeyInUse, "held again")

	// it dies and another instance takes the key first
	dropLockConn(t, first, other)
	require.NoError(t, other.LockKey(ctx, key))
	require.ErrorIs(t, first.CheckLock(ctx), ErrKeyInUse)
	watchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.ErrorIs(t, first.WatchLock(watchCtx, 10*time.Millisecond), ErrKeyInUse)

	require.NoError(t, other.Close())
	require.NoError(t, other.CheckLock(ctx), "closed: nothing to watch")
	require.NoError(t, testRepo(t).WatchLock(ctx, time.Millisecond), "never locked: nothing to watch")
	stopped, stop := context.WithCancel(ctx)
	stop()
	require.NoError(t, first.WatchLock(stopped, time.Hour))
}

func TestNewRepositoryErrors(t *testing.T) {
	_, err := NewRepository(t.Context(), "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	require.Error(t, err)
}

// testRepo needs the compose postgres (make regtest-up).
func testRepo(t *testing.T) *Repository {
	t.Helper()
	dsn := os.Getenv("DELEGATEE_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres@localhost:5432/delegatee?sslmode=disable"
	}
	repo, err := NewRepository(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func settlementsOf(t *testing.T, repo *Repository, delegationID int64) []domain.Settlement {
	t.Helper()
	all, err := repo.ListSettlements(t.Context())
	require.NoError(t, err)
	return slices.DeleteFunc(all, func(s domain.Settlement) bool { return s.DelegationID != delegationID })
}

// dropLockConn terminates the backend holding r's lock, from other.
func dropLockConn(t *testing.T, r, other *Repository) {
	t.Helper()
	var pid int
	require.NoError(t, r.lock.QueryRowContext(t.Context(), "SELECT pg_backend_pid()").Scan(&pid))
	_, err := other.db.ExecContext(t.Context(), "SELECT pg_terminate_backend($1)", pid)
	require.NoError(t, err)
}
