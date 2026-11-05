package template

import (
	"slices"

	"github.com/arkade-os/delegatee/pkg/template/internal/schema"
)

// compiler turns a typed document into a Template: names become indexes, bindings are typed and
// cross-part rules are checked.
type compiler struct {
	artifacts map[string][]byte
	doc       *schema.Template
	t         *Template
	named     map[string]bool // variables and secrets some binding uses
}

func compile(doc *schema.Template, artifacts map[string][]byte) (*Template, error) {
	c := &compiler{artifacts: artifacts, doc: doc, named: map[string]bool{}, t: &Template{
		typ: Type(doc.Type), variables: map[string]string{}, secrets: map[string]secret{},
	}}
	if err := c.declarations(); err != nil {
		return nil, err
	}
	for i := range doc.Inputs {
		if err := c.input(&doc.Inputs[i]); err != nil {
			return nil, err
		}
	}
	if err := c.secretBodies(); err != nil {
		return nil, err
	}
	for i := range doc.Outputs {
		if err := c.output(&doc.Outputs[i]); err != nil {
			return nil, err
		}
	}
	for _, check := range []func() error{
		c.t.checkPrograms, c.t.checkBalances, c.fees, c.packets, c.trigger, c.t.checkPlacement, c.confineTaptrees,
	} {
		if err := check(); err != nil {
			return nil, err
		}
	}
	return c.t, nil
}

func (c *compiler) inputIndex(name, what string) (int, error) {
	i := slices.IndexFunc(c.t.inputs, func(in input) bool { return in.name == name })
	if i < 0 {
		return 0, bad("%s names no input: %q", what, name)
	}
	return i, nil
}

// intVariable returns the literal, or the name of the int variable the value reads.
func (c *compiler) intVariable(v schema.IntOrVar) (int64, string, error) {
	if v.Int != nil {
		return *v.Int, "", nil
	}
	if c.t.variables[v.Var] != "int" {
		return 0, "", bad("%q is not an int variable", "<"+v.Var+">")
	}
	return 0, v.Var, nil
}

// slotType resolves a slot's type, which defaults to the template's and may differ only in an intent.
func (c *compiler) slotType(given string) (bool, error) {
	def := Offchain
	if c.t.typ == Onchain {
		def = Onchain
	}
	typ := def
	if given != "" {
		typ = Type(given)
	}
	if c.t.typ != Intent && typ != def {
		return false, bad("%s slot in a template of type %s", typ, c.t.typ)
	}
	return typ == Onchain, nil
}

// confineTaptrees: a taptree variable escapes the push size cap, so it fills nothing else.
func (c *compiler) confineTaptrees() error {
	for _, in := range c.t.inputs {
		if v := in.contract.taptree; v != "" && c.named[v] {
			return bad("taptree variable %q is used outside the taptree field", v)
		}
	}
	return nil
}
