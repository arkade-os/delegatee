module github.com/arkade-os/delegatee

go 1.26.6

replace github.com/arkade-os/delegatee/api-spec => ./api-spec

replace github.com/arkade-os/delegatee/pkg/template => ./pkg/template

require (
	github.com/arkade-os/arkd/pkg/ark-lib v0.8.1-0.20260901090427-f863e4847193
	github.com/arkade-os/arkd/pkg/client-lib v0.0.0-20260901090427-f863e4847193
	github.com/arkade-os/arkd/pkg/client-wallet v0.0.0-20260901090427-f863e4847193
	github.com/arkade-os/delegatee/api-spec v0.0.0-00010101000000-000000000000
	github.com/arkade-os/delegatee/pkg/template v0.0.0
	github.com/arkade-os/emulator/pkg/arkade v0.0.0-20260925153657-d928b6ed57ee
	github.com/arkade-os/emulator/pkg/client v0.0.0-20260925153657-d928b6ed57ee
	github.com/btcsuite/btcd/address/v2 v2.0.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btcd/btcutil/v2 v2.0.1
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0
	github.com/btcsuite/btcd/psbt/v2 v2.0.0
	github.com/btcsuite/btcd/txscript/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.1
	github.com/btcsuite/btcwallet v0.18.0
	github.com/golang-migrate/migrate/v4 v4.18.1
	github.com/lib/pq v1.10.9
	github.com/meshapi/grpc-api-gateway v0.1.0
	github.com/prometheus/client_golang v1.23.2
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.56.0
	golang.org/x/sync v0.22.0
	golang.org/x/time v0.15.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	cel.dev/expr v0.25.2 // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/arkade-os/arkd/api-spec v0.0.0-20260901090427-f863e4847193 // indirect
	github.com/arkade-os/arkd/pkg/errors v0.0.0-20260901090427-f863e4847193 // indirect
	github.com/arkade-os/emulator/api-spec v0.0.0-20260903164234-4feb9eaa81b4 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/btcsuite/btcd v0.26.2 // indirect
	github.com/btcsuite/btcd/v2transport v1.1.0 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/btcsuite/btclog/v2 v2.0.1-0.20250728225537-6090e87c6c5b // indirect
	github.com/btcsuite/btcwallet/wallet/txauthor v1.4.0 // indirect
	github.com/btcsuite/btcwallet/wallet/txrules v1.3.0 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.3.0 // indirect
	github.com/btcsuite/btcwallet/walletdb v1.6.0 // indirect
	github.com/btcsuite/btcwallet/wtxmgr v1.6.0 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/consensys/gnark-crypto v0.19.2 // indirect
	github.com/containerd/continuity v0.4.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/decred/dcrd/lru v1.1.3 // indirect
	github.com/google/cel-go v0.30.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/neutrino v0.18.0 // indirect
	github.com/lightninglabs/neutrino/cache v1.1.4 // indirect
	github.com/lightningnetwork/lnd v0.21.0-beta.rc2.0.20260828055859-d24719e0a3d3 // indirect
	github.com/lightningnetwork/lnd/clock v1.1.1 // indirect
	github.com/lightningnetwork/lnd/fn/v2 v2.0.9 // indirect
	github.com/lightningnetwork/lnd/queue v1.2.0 // indirect
	github.com/lightningnetwork/lnd/ticker v1.1.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.4.0 // indirect
	github.com/ltcsuite/ltcd/chaincfg/chainhash v1.0.2 // indirect
	github.com/miekg/dns v1.1.62 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/tidwall/gjson v1.19.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	go.etcd.io/etcd/api/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/v2 v2.305.15 // indirect
	go.etcd.io/etcd/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/raft/v3 v3.5.15 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.43.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.10.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20250811191247-51f88131bc50 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	modernc.org/libc v1.61.0 // indirect
)
