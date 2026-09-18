package grpcservice

import (
	"context"
	"time"

	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/prometheus/client_golang/prometheus"
)

// collector reads the service on every scrape: nothing to keep in sync.
type collector struct {
	svc application.Service
}

var (
	descActive     = prometheus.NewDesc("delegatee_delegations_active", "Active delegations, whatever their key.", nil, nil)
	descForeign    = prometheus.NewDesc("delegatee_delegations_foreign", "Active delegations registered under another key, which this instance cannot renew.", nil, nil)
	descVtxos      = prometheus.NewDesc("delegatee_vtxos_watched", "Spendable vtxos at the addresses this instance renews, as of the last scan.", nil, nil)
	descSats       = prometheus.NewDesc("delegatee_sats_watched", "Amount of those vtxos, in sats.", nil, nil)
	descLate       = prometheus.NewDesc("delegatee_vtxos_late", "Vtxos renewable for a while and still not renewed. Alert on this.", nil, nil)
	descLateSats   = prometheus.NewDesc("delegatee_sats_late", "Amount of the late vtxos, in sats.", nil, nil)
	descRenewing   = prometheus.NewDesc("delegatee_vtxos_renewing", "Vtxos in the batch session in flight.", nil, nil)
	descLastScan   = prometheus.NewDesc("delegatee_last_scan_timestamp_seconds", "Unix time of the last completed scan, 0 before the first.", nil, nil)
	descRenewals   = prometheus.NewDesc("delegatee_renewals_total", "Vtxo renewals since the process started, by result.", []string{"result"}, nil)
	descDependency = prometheus.NewDesc("delegatee_dependency_up", "1 when the dependency answers, 0 otherwise.", []string{"name"}, nil)
)

func (c collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		descActive, descForeign, descVtxos, descSats, descLate, descLateSats, descRenewing, descLastScan, descRenewals, descDependency,
	} {
		ch <- d
	}
}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}

	st := c.svc.Status()
	var vtxos, late int
	var sats, lateSats uint64
	for _, h := range st.Holdings {
		vtxos, sats, late, lateSats = vtxos+h.Vtxos, sats+h.Amount, late+h.Late, lateSats+h.LateAmount
	}
	gauge(descVtxos, float64(vtxos))
	gauge(descSats, float64(sats))
	gauge(descLate, float64(late))
	gauge(descLateSats, float64(lateSats))
	gauge(descRenewing, float64(st.RenewingVtxos))
	if !st.LastScan.IsZero() {
		gauge(descLastScan, float64(st.LastScan.Unix()))
	} else {
		gauge(descLastScan, 0)
	}
	ch <- prometheus.MustNewConstMetric(descRenewals, prometheus.CounterValue, float64(st.Renewed), "ok")
	ch <- prometheus.MustNewConstMetric(descRenewals, prometheus.CounterValue, float64(st.Failed), "failed")

	if active, err := c.svc.CountActive(ctx); err == nil {
		gauge(descActive, float64(active))
		if !st.LastScan.IsZero() {
			gauge(descForeign, float64(max(0, int(active)-len(st.Holdings))))
		}
	}
	for name, err := range c.svc.Health(ctx) {
		up := 1.0
		if err != nil {
			up = 0
		}
		gauge(descDependency, up, name)
	}
}
