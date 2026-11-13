package v1

import (
	"fmt"

	"github.com/arkade-os/executor/pkg/template/artifact"
)

func Parse(raw []byte, artifacts map[string][]byte) (*Template, error) {
	d, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	parsed := map[string]*artifact.Artifact{}
	for _, id := range d.ArtifactIDs() {
		doc, ok := artifacts[id]
		if !ok {
			continue
		}
		if parsed[id], err = artifact.Parse(doc); err != nil {
			return nil, fmt.Errorf("%w: artifact %s: %w", ErrInvalidTemplate, id, err)
		}
	}
	return Compile(d, parsed)
}

func ArtifactIDs(raw []byte) ([]string, error) {
	d, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	return d.ArtifactIDs(), nil
}

type parsedArtifact struct {
	ID         string
	Definition Definition
}

func ParseArtifact(raw []byte) (*parsedArtifact, error) {
	a, err := artifact.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &parsedArtifact{ID: a.ID(), Definition: a.Definition()}, nil
}
