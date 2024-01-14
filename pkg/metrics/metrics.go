package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type TFAMetrics struct {
	registry *prometheus.Registry

	authentications *prometheus.CounterVec
}

func (m *TFAMetrics) Init() {
	m.registry = prometheus.NewRegistry()
	factory := promauto.With(m.registry)

	m.authentications = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "tfa_authentications",
		Help: "The number of authentications",
	}, []string{"success"})
}

func (m *TFAMetrics) HTTPHandler() http.Handler {
	return promhttp.InstrumentMetricHandler(
		m.registry,
		promhttp.HandlerFor(
			prometheus.Gatherers{
				m.registry,
				prometheus.DefaultGatherer,
			},
			promhttp.HandlerOpts{},
		),
	)
}

func (m *TFAMetrics) RecordAuthentication(success bool) {
	m.authentications.
		WithLabelValues(strconv.FormatBool(success)).
		Add(1)
}
