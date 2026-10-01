package ports

import clientlib "github.com/arkade-os/arkd/pkg/client-lib"

// Explorer reads and writes the chain for onchain inputs and transactions.
type Explorer interface {
	GetUtxos(addresses []string) ([]clientlib.ExplorerUtxo, error)
	GetTxHex(txid string) (string, error)
	GetTxOutspends(txid string) ([]clientlib.SpentStatus, error)
	Confirmations(txid string) (int, error)
	Broadcast(txs ...string) (string, error)
	GetFeeRate() (float64, error) // sat/vB
}
