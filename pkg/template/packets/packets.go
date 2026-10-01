// Package packets encodes template extension packets: type 2 (state) and type 5 (advertisement).
package packets

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	// TypeState is the packet type of a template's state.
	TypeState uint8 = 2
	// TypeAdvertisement is the packet type naming the templates that claim outputs.
	TypeAdvertisement uint8 = 5

	advertisementVersion = 0x01
	templateIDLen        = 32
	// counts the whole body, version byte and length prefixes included
	maxAdvertisementLen = 520
)

// ErrInvalidAdvertisement marks a malformed packet 5 body.
var ErrInvalidAdvertisement = errors.New("packets: invalid advertisement")

// Record is a template id and the output indexes it claims.
type Record struct {
	Template [32]byte
	Outputs  []uint16
}

// EncodeAdvertisement encodes records as a packet 5 body:
//
//	version:u8 (0x01) || record...
//	record = body_length:u16le || body
//	body   = template_id[32] || output_index:u16le...
//
// Records are sorted by their smallest output index; a record's own indexes keep their order.
func EncodeAdvertisement(records []Record) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("packets: advertisement needs at least one record")
	}
	for i, r := range records {
		if len(r.Outputs) == 0 {
			return nil, fmt.Errorf("packets: record %d needs at least one output", i)
		}
	}

	sorted := slices.Clone(records)
	slices.SortStableFunc(sorted, func(x, y Record) int { return cmp.Compare(slices.Min(x.Outputs), slices.Min(y.Outputs)) })

	out := []byte{advertisementVersion}
	for i, r := range sorted {
		body := make([]byte, 0, templateIDLen+2*len(r.Outputs))
		body = append(body, r.Template[:]...)
		for _, o := range r.Outputs {
			body = binary.LittleEndian.AppendUint16(body, o)
		}
		if len(body) > 0xffff {
			return nil, fmt.Errorf("packets: record %d body too long: %d bytes", i, len(body))
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(len(body)))
		out = append(out, body...)
	}

	if len(out) > maxAdvertisementLen {
		return nil, fmt.Errorf("packets: advertisement too long: %d bytes, max %d", len(out), maxAdvertisementLen)
	}
	return out, nil
}

// DecodeAdvertisement decodes a packet 5 body, keeping the records in their encoded order.
func DecodeAdvertisement(body []byte) ([]Record, error) {
	if len(body) > maxAdvertisementLen {
		return nil, fmt.Errorf("%w: advertisement too long: %d bytes, max %d", ErrInvalidAdvertisement, len(body), maxAdvertisementLen)
	}
	if len(body) < 1 {
		return nil, fmt.Errorf("%w: empty advertisement body", ErrInvalidAdvertisement)
	}
	if body[0] != advertisementVersion {
		return nil, fmt.Errorf("%w: unsupported advertisement version 0x%02x", ErrInvalidAdvertisement, body[0])
	}

	rest := body[1:]
	var records []Record
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, fmt.Errorf("%w: truncated record length", ErrInvalidAdvertisement)
		}
		recLen := int(binary.LittleEndian.Uint16(rest[:2]))
		rest = rest[2:]
		if recLen > len(rest) {
			return nil, fmt.Errorf("%w: truncated record body: want %d bytes, have %d", ErrInvalidAdvertisement, recLen, len(rest))
		}
		recBody := rest[:recLen]
		rest = rest[recLen:]

		rec, err := decodeRecord(recBody)
		if err != nil {
			return nil, fmt.Errorf("%w: record %d: %w", ErrInvalidAdvertisement, len(records), err)
		}
		records = append(records, rec)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("%w: advertisement has no records", ErrInvalidAdvertisement)
	}
	return records, nil
}

func decodeRecord(body []byte) (Record, error) {
	if len(body) < templateIDLen {
		return Record{}, fmt.Errorf("body shorter than template id: %d bytes", len(body))
	}
	var rec Record
	copy(rec.Template[:], body[:templateIDLen])

	indexBytes := body[templateIDLen:]
	if len(indexBytes)%2 != 0 {
		return Record{}, fmt.Errorf("odd number of index bytes: %d", len(indexBytes))
	}
	if len(indexBytes) == 0 {
		return Record{}, fmt.Errorf("record has no output indexes")
	}

	rec.Outputs = make([]uint16, len(indexBytes)/2)
	for i := range rec.Outputs {
		rec.Outputs[i] = binary.LittleEndian.Uint16(indexBytes[2*i : 2*i+2])
	}
	return rec, nil
}

// Raw wraps body as an unparsed extension packet of type typ.
func Raw(typ uint8, body []byte) extension.Packet {
	return extension.UnknownPacket{PacketType: typ, Data: body}
}

// Find returns the body of the first packet of type typ in tx's extension output.
func Find(tx *wire.MsgTx, typ uint8) ([]byte, bool) {
	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil {
		return nil, false
	}
	p := ext.GetPacketByType(typ)
	if p == nil {
		return nil, false
	}
	body, err := p.Serialize()
	if err != nil {
		return nil, false
	}
	return body, true
}
