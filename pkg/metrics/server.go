package metrics

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

// Server exposes a /metrics HTTP endpoint for Prometheus scraping.
type Server struct {
	srv *http.Server
}

// NewServer creates a Server that serves the metrics registered in reg on addr.
// addr should be a listen address such as ":9090" or "127.0.0.1:9090".
func NewServer(addr string, reg prometheus.Gatherer) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))
	return &Server{
		srv: &http.Server{
			Addr:    addr,
			Handler: mux,
			// Bound request phases so a slow client cannot tie up the endpoint
			// (Slowloris). ReadHeaderTimeout is the key mitigation.
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

// Start begins listening in a background goroutine.
func (s *Server) Start() {
	go func() {
		log.Info().Str("addr", s.srv.Addr).Msg("Metrics server listening")
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("Metrics server error")
		}
	}()
}

// Stop shuts down the server gracefully using ctx.
func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
