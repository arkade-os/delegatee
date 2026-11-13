package template

import (
	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/arkade-os/executor/pkg/template/internal/model"
)

type Type = model.Type

const (
	Proof   = model.Proof
	Virtual = model.Virtual
	Onchain = model.Onchain
)

type Schedule = model.Schedule
type Slot = model.Slot
type Keys = model.Keys
type Context = model.Context
type Source = model.Source
type Asset = model.Asset
type Fee = model.Fee
type Action = model.Action
type TriggerKeys = model.TriggerKeys
type Capture = model.Capture
type Bindings = model.Bindings
type Runtime = model.Runtime
type BuildRequest = model.BuildRequest
type Field = artifact.Field
type Struct = artifact.Struct
type WitnessItem = artifact.WitnessItem
type Leaf = artifact.Leaf
type Covenant = artifact.Covenant
type Function = artifact.Function
type Definition = artifact.Definition

// Artifact is a mutable snapshot kept for existing callers; prefer artifact.Artifact.
type Artifact struct {
	ID         string
	Definition Definition
}

func ParseArtifact(raw []byte) (*Artifact, error) {
	a, err := artifact.Parse(raw)
	if err != nil {
		return nil, wrap("artifact", err)
	}
	return &Artifact{ID: a.ID(), Definition: a.Definition()}, nil
}
