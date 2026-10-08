package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

var (
	ErrDelegationNotFound      = errors.New("delegation not found")
	ErrDelegationAlreadyExists = errors.New("delegation already active")
	ErrTemplateNotFound        = errors.New("template not found")
	ErrTemplateDisabled        = errors.New("template is disabled")
	ErrTemplateInUse           = errors.New("template is referenced by a delegation")
	ErrArtifactNotFound        = errors.New("artifact not found")
	ErrArtifactInUse           = errors.New("artifact is referenced by a template")
	ErrCapReached              = errors.New("cap reached")
	ErrBlocked                 = errors.New("an operator cancelled this delegation: registering it again needs the operator to resume it")
	ErrNotCancelled            = errors.New("delegation is not cancelled")
)

// done means a one-shot whose coins were all spent.
const (
	DelegationStatusActive    = "active"
	DelegationStatusCancelled = "cancelled"
	DelegationStatusExpired   = "expired"
	DelegationStatusDone      = "done"
)

const (
	TemplateStatusActive   = "active"
	TemplateStatusDisabled = "disabled"
)

type Artifact struct {
	ID        string
	Document  []byte
	CreatedAt time.Time
}

type ArtifactRepository interface {
	// CreateArtifact keeps the first bytes stored under id, and fails with ErrCapReached at max (0: no cap) artifacts.
	CreateArtifact(ctx context.Context, id string, document []byte, max int) (*Artifact, error)
	GetArtifact(ctx context.Context, id string) (*Artifact, error)
	// ListArtifacts omits documents, newest first.
	ListArtifacts(ctx context.Context) ([]Artifact, error)
	// DeleteArtifact fails with ErrArtifactInUse while a template references it.
	DeleteArtifact(ctx context.Context, id string) error
}

type Template struct {
	ID          string
	Document    []byte
	ArtifactIDs []string
	Params      []Param // cached from Parse, for listing and args validation
	Status      string
	// Failures counts consecutive cycles in which every intent was rejected.
	Failures int
	// Trusted templates are never disabled by failures.
	Trusted   bool
	CreatedAt time.Time
}

type TemplateRepository interface {
	// CreateTemplate returns the stored template when its id exists, and fails with ErrCapReached at max (0: no cap) templates.
	CreateTemplate(ctx context.Context, t Template, max int) (*Template, error)
	GetTemplate(ctx context.Context, id string) (*Template, error)
	// ListTemplates filters by a non-empty status and omits documents.
	ListTemplates(ctx context.Context, status string) ([]Template, error)
	// SetTemplateStatus resets the failure counter when the status is active.
	SetTemplateStatus(ctx context.Context, id, status string) error
	SetTemplateTrusted(ctx context.Context, id string, trusted bool) error
	// DeleteTemplate fails with ErrTemplateInUse while any delegation references it.
	DeleteTemplate(ctx context.Context, id string) error
	// RecordTemplateOutcome resets failures on success and disables the template at maxFailures.
	RecordTemplateOutcome(ctx context.Context, id string, success bool, maxFailures int) (failures int, status string, err error)
}

// Param is a user-supplied variable of a scalar type (pubkey, int, bytes32, ...).
type Param struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Delegation is an instance of a template.
type Delegation struct {
	ID int64
	// unique among active rows
	Fingerprint    string
	Address        string // slot 0 address of a watch; empty otherwise
	TemplateID     string
	Variables      map[string]string
	ParentID       int64      // the delegation whose settled transaction advertised this one; 0 for a watch
	ExpiresAt      *time.Time // watches and spends; nil never expires
	DelegatePubKey string     // the cosigner key it was instantiated with
	// one per template input; a watch has exactly one
	Slots     []SlotBinding
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsWatch: RegisterDelegation watches an address, a successor binds outpoints.
func (d *Delegation) IsWatch() bool {
	return d.Address != "" && !slices.ContainsFunc(d.Slots, func(s SlotBinding) bool { return s.Outpoint != "" })
}

// IsSpend: bound by RegisterSpend.
func (d *Delegation) IsSpend() bool {
	return d.Address == "" && d.ExpiresAt != nil
}

type SlotBinding struct {
	Name       string   `json:"name"`
	Onchain    bool     `json:"onchain"`
	Tapscripts []string `json:"tapscripts"`         // what the scan checks the instance against
	Script     string   `json:"script"`             // hex pkScript
	Outpoint   string   `json:"outpoint,omitempty"` // "txid:vout" when bound, empty for a watch
}

// Fingerprint is hex(sha256(template_id || 0 || variables as JSON with
// sorted keys || 0 || outpoints joined by ",")).
func Fingerprint(templateID string, variables map[string]string, outpoints []string) string {
	if variables == nil {
		variables = map[string]string{}
	}
	vars, _ := json.Marshal(variables) // a map of strings always marshals, keys sorted
	h := sha256.New()
	h.Write([]byte(templateID))
	h.Write([]byte{0})
	h.Write(vars)
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(outpoints, ",")))
	return hex.EncodeToString(h.Sum(nil))
}

type Renewal struct {
	DelegationID   int64
	Outpoints      []string
	CommitmentTxid string
	Success        bool
	Error          string
	AttemptedAt    time.Time
}

// Settlement is a transaction the daemon built to spend a delegation's coins, kept until its successors exist.
type Settlement struct {
	Txid string
	// what the indexer or the chain reports spending the coins: the ark, commitment or onchain txid
	SpentBy      string
	DelegationID int64
	Tx           []byte         // serialized
	Outpoints    map[int]string // output index of Tx -> the outpoint paying it
	Sources      [][]byte       // serialized transactions creating Outpoints
	Coins        []string
	Checkpoints  []string // the unsigned checkpoints of an offchain tx the daemon submits itself
	Finals       []string // final checkpoints while arkd waits for FinalizeTx
	Landed       bool     // Tx is known to have spent the coins: only the successors are left
	CreatedAt    time.Time
}

type SettlementRepository interface {
	// SaveSettlement updates Finals and Landed of the settlement of the same Txid and SpentBy.
	SaveSettlement(ctx context.Context, s Settlement) error
	ListSettlements(ctx context.Context) ([]Settlement, error)
	DeleteSettlement(ctx context.Context, txid, spentBy string) error
}

type DelegationRepository interface {
	// Create returns the active delegation of the same fingerprint, else fails with ErrCapReached at max (0: no cap) active ones.
	Create(ctx context.Context, d Delegation, max int) (*Delegation, error)
	// Get returns the newest delegation watching address, an active one first.
	Get(ctx context.Context, address string) (*Delegation, error)
	GetByID(ctx context.Context, id int64) (*Delegation, error)
	// GetByFingerprint returns the newest delegation with the fingerprint.
	GetByFingerprint(ctx context.Context, fingerprint string) (*Delegation, error)
	GetActiveByOutpoint(ctx context.Context, outpoint string) (*Delegation, error)
	List(ctx context.Context, status string) ([]Delegation, error)
	// ListPage lists up to limit delegations of a non-empty status, newest first, with ids below a non-zero cursor.
	ListPage(ctx context.Context, status string, cursor int64, limit int) ([]Delegation, error)
	// SetStatus leaves a stopped delegation as it is.
	SetStatus(ctx context.Context, id int64, status string) error
	// Resume sets a cancelled delegation active again; ErrNotCancelled otherwise.
	Resume(ctx context.Context, id int64) error
	// Expire marks active delegations expiring at or before `before`.
	Expire(ctx context.Context, before time.Time) (int64, error)
	CountActive(ctx context.Context) (int64, error)
	// CountDelegationsByTemplate counts delegations of any status.
	CountDelegationsByTemplate(ctx context.Context) (map[string]int64, error)

	RecordRenewal(ctx context.Context, renewal Renewal) error
	ListRenewals(ctx context.Context, delegationID int64, limit int) ([]Renewal, error)
	LastRenewals(ctx context.Context) (map[int64]Renewal, error)
	// PruneRenewals keeps each delegation's latest renewal.
	PruneRenewals(ctx context.Context, before time.Time) error
}
