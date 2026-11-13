package delegation

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/executor/pkg/template"
)

// Stream is an operator's standing rule: its template's trigger is run against arkd's transactions.
type Stream struct {
	ID         int64
	TemplateID string
	Variables  map[string]string // lower-case hex; the trigger captures the others
	Status     string            // active or cancelled
	CreatedAt  time.Time
}

type StreamRepository interface {
	// AddOrUpdate inserts s when its id is zero, or loads into s the stream of the same template
	// and variables whatever its status; else it persists the status of s, ErrStreamNotFound when
	// no row has its id.
	AddOrUpdate(ctx context.Context, s *Stream) error
	Get(ctx context.Context, id int64) (*Stream, error)
	// List returns the streams with status, all of them when it is empty, oldest first.
	List(ctx context.Context, status string) ([]Stream, error)
}

type StreamParams struct {
	Template   *template.Template
	Variables  map[string]string
	MinExpiry  time.Duration
	Encryption bool // an encryption key is configured
}

type SpawnParams struct {
	Stream   Stream
	Template *template.Template
	Output   []byte            // script of the streamed output
	Captured map[string]string // what the trigger captured for it
	Now      time.Time
	Keys     template.Keys // Delegate is the stream's key
	Decrypt  func([]byte) ([]byte, error)
	Network  arklib.Network
}

// NewStream checks that the trigger of a template can run with variables: each declared variable is
// given or captured by the trigger, exactly one of the two.
func NewStream(p StreamParams) (*Stream, error) {
	triggers := p.Template.Triggers()
	if len(triggers) != 1 {
		return nil, ErrNotStream // the registry refuses a trigger of several rules
	}
	trigger := triggers[0]
	switch {
	case len(p.Template.Sealed()) > 0 && !p.Encryption:
		return nil, ErrNoEncryptionKey
	case trigger.TTL() < p.MinExpiry:
		return nil, fmt.Errorf(
			"%w: the trigger's delegations expire before %s", ErrInvalidArgs, p.MinExpiry,
		)
	}
	declared := map[string]bool{}
	for _, v := range p.Template.Variables() {
		declared[v.Name] = true
		if _, given := p.Variables[v.Name]; slices.Contains(trigger.Captured(), v.Name) == given {
			return nil, fmt.Errorf(
				"%w: %q is given or captured by the trigger, exactly one of the two",
				ErrInvalidArgs, v.Name,
			)
		}
	}
	for name, value := range p.Variables {
		if raw, err := hex.DecodeString(
			value,
		); !declared[name] || err != nil ||
			hex.EncodeToString(raw) != value {
			return nil, fmt.Errorf(
				"%w: %q is undeclared or not lower-case hex", ErrInvalidArgs, name,
			)
		}
	}
	if p.Variables == nil {
		p.Variables = map[string]string{}
	}
	return &Stream{TemplateID: p.Template.ID(), Variables: p.Variables, Status: StatusActive}, nil
}

// Given is what the stream's variables hold.
func (s Stream) Given() (map[string][]byte, error) { return decodeVariables(s.Variables) }

func (s *Stream) Cancel() error {
	if s.Status != StatusActive {
		return ErrNotActive
	}
	s.Status = StatusCancelled
	return nil
}

// Spawn is the delegation of the stream's template over a streamed output, expiring after the
// trigger's lifetime; the template must lock exactly that output.
func Spawn(p SpawnParams) (*Delegation, error) {
	variables := maps.Clone(p.Stream.Variables)
	maps.Copy(variables, p.Captured)
	w := DelegationParams{
		Template: p.Template, Variables: variables, Keys: p.Keys, Decrypt: p.Decrypt,
		Network: p.Network,
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	expiresAt := p.Now.Add(p.Template.Triggers()[0].TTL())
	w.ExpiresAt = &expiresAt
	d, err := w.build(p.Stream.ID)
	if err != nil {
		return nil, err
	}
	if d.Inputs[0].Script != hex.EncodeToString(p.Output) {
		return nil, fmt.Errorf("%w: it locks %s", ErrIneligible, d.Inputs[0].Script)
	}
	return d, nil
}
