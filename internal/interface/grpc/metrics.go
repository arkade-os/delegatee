package grpc

import (
	"context"
	"time"

	executionapp "github.com/arkade-os/delegatee/internal/core/application/execution"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/interface/grpc/handlers"
	"github.com/prometheus/client_golang/prometheus"
)

const scrapeTimeout = 5 * time.Second

type StatusSource interface {
	Status(ctx context.Context, forecast bool) (executionapp.Status, error)
}

// collector reads the status and the health on every scrape, so there is nothing to keep in sync.
type collector struct {
	status StatusSource
	health handlers.Health
}

var (
	descActive           = prometheus.NewDesc("delegatee_delegations_active", "Active delegations.", nil, nil)
	descQueued           = prometheus.NewDesc("delegatee_entries_queued", "Entries waiting to be registered at arkd.", nil, nil)
	descRegistered       = prometheus.NewDesc("delegatee_entries_registered", "Entries registered at arkd, waiting for a batch.", nil, nil)
	descLate             = prometheus.NewDesc("delegatee_coins_late", "Coins forecast to miss their deadline. Alert on this.", nil, nil)
	descCoins            = prometheus.NewDesc("delegatee_coins_watched", "Present coins at the watched scripts.", nil, nil)
	descAmount           = prometheus.NewDesc("delegatee_sats_watched", "Amount of the present coins, in sats.", nil, nil)
	descTip              = prometheus.NewDesc("delegatee_chain_tip_height", "Height of the chain's latest block, 0 before the first.", nil, nil)
	descAttempts         = prometheus.NewDesc("delegatee_attempts_total", "Attempts that ended since the process started, by status.", []string{"status"}, nil)
	descTemplateFailures = prometheus.NewDesc("delegatee_template_failures_total", "Failed attempts charged to their template since the process started.", nil, nil)
	descDependency       = prometheus.NewDesc("delegatee_dependency_up", "1 when the dependency is healthy, 0 otherwise.", []string{"name"}, nil)
)

// Describe sends nothing, which makes the collector unchecked.
func (c collector) Describe(chan<- *prometheus.Desc) {}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	metric := func(d *prometheus.Desc, kind prometheus.ValueType, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, kind, v, labels...)
	}
	if st, err := c.status.Status(ctx, false); err == nil {
		metric(descActive, prometheus.GaugeValue, float64(st.Active))
		metric(descQueued, prometheus.GaugeValue, float64(st.Queued))
		metric(descRegistered, prometheus.GaugeValue, float64(st.Registered))
		metric(descLate, prometheus.GaugeValue, float64(st.Late))
		metric(descCoins, prometheus.GaugeValue, float64(st.Coins))
		metric(descAmount, prometheus.GaugeValue, float64(st.Amount))
		metric(descTip, prometheus.GaugeValue, float64(st.Tip.Height))
		metric(descAttempts, prometheus.CounterValue, float64(st.Succeeded), string(delegation.Succeeded))
		metric(descAttempts, prometheus.CounterValue, float64(st.Failed), string(delegation.Failed))
		metric(descTemplateFailures, prometheus.CounterValue, float64(st.TemplateFailures))
	}
	for _, e := range c.health.Check(ctx) {
		up := 1.0
		if e.Err != nil {
			up = 0
		}
		metric(descDependency, prometheus.GaugeValue, up, e.Name)
	}
}
