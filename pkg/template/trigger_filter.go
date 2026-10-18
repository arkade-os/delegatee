package template

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Filter is a conservative Arkd CEL prefilter; Match remains authoritative.
func (tr *Trigger) Filter(keys TriggerKeys) string {
	clauses := []string{fmt.Sprintf("has(tx.extension) && hasPacket(tx.extension, %d)", tr.packet)}
	for _, r := range tr.require {
		var alternatives []string
		for _, value := range r.values(keys) {
			if tr.raw {
				alternatives = append(alternatives, fmt.Sprintf("tx.extension[%d] == '%s'", tr.packet, hex.EncodeToString(value)))
				continue
			}
			if len(value) > math.MaxUint16 {
				continue
			}
			tag, _ := strconv.Atoi(strings.TrimPrefix(r.source, "tlv:"))
			record := binary.BigEndian.AppendUint16([]byte{byte(tag)}, uint16(len(value)))
			record = append(record, value...)
			alternatives = append(alternatives, fmt.Sprintf("tx.extension[%d].contains('%s')", tr.packet, hex.EncodeToString(record)))
		}
		if len(alternatives) == 0 {
			return "false"
		}
		clauses = append(clauses, "("+strings.Join(alternatives, " || ")+")")
	}
	filter := strings.Join(clauses, " && ")
	if len(filter) > 16<<10 {
		return clauses[0]
	}
	return filter
}
