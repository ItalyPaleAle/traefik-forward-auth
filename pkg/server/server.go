package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/metrics"
)

// Server is the server based on Gin
type Server struct {
	appRouter *gin.Engine
	metrics   metrics.TFAMetrics

	// Servers
	appSrv     *http.Server
	metricsSrv *http.Server

	running atomic.Bool
	wg      sync.WaitGroup

	// Listeners for the app and metrics servers
	// These can be used for testing without having to start an actual TCP listener
	appListener     net.Listener
	metricsListener net.Listener

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server)
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	Log *zerolog.Logger

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server)
}

// NewServer creates a new Server object and initializes it
func NewServer(opts NewServerOpts) (*Server, error) {
	s := &Server{
		addTestRoutes: opts.addTestRoutes,
	}

	// Init the object
	err := s.init(opts.Log)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Init the Server object and create a Gin server
func (s *Server) init(log *zerolog.Logger) error {
	// Init the Prometheus metrics
	s.metrics.Init()

	// Init the app server
	err := s.initAppServer(log)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initAppServer(log *zerolog.Logger) (err error) {
	// Create the Gin router and add various middlewares
	s.appRouter = gin.New()
	s.appRouter.Use(gin.Recovery())
	s.appRouter.Use(s.MiddlewareRequestId)
	s.appRouter.Use(s.MiddlewareLogger(log))

	// Healthz route
	s.appRouter.GET("/healthz", gin.WrapF(s.RouteHealthzHandler))

	// Test routes, that are enabled when running tests only
	if s.addTestRoutes != nil {
		s.addTestRoutes(s)
	}

	return nil
}

// Run the web server
// Note this function is blocking, and will return only when the servers are shut down via context cancellation.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("server is already running")
	}
	defer s.running.Store(false)
	defer s.wg.Wait()

	cfg := config.Get()

	// App server
	s.wg.Add(1)
	err := s.startAppServer(ctx)
	if err != nil {
		return fmt.Errorf("failed to start app server: %w", err)
	}
	defer func() {
		// Handle graceful shutdown
		defer s.wg.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.appSrv.Shutdown(shutdownCtx)
		shutdownCancel()
		if err != nil {
			// Log the error only (could be context canceled)
			zerolog.Ctx(ctx).Warn().
				Err(err).
				Msg("App server shutdown error")
		}
	}()

	// Metrics server
	if cfg.EnableMetrics {
		s.wg.Add(1)
		err = s.startMetricsServer(ctx)
		if err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
		defer func() {
			// Handle graceful shutdown
			defer s.wg.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			err := s.metricsSrv.Shutdown(shutdownCtx)
			shutdownCancel()
			if err != nil {
				// Log the error only (could be context canceled)
				zerolog.Ctx(ctx).Warn().
					Err(err).
					Msg("Metrics server shutdown error")
			}
		}()
	}

	// Block until the context is canceled
	<-ctx.Done()

	// Servers are stopped with deferred calls
	return nil
}

func (s *Server) startAppServer(ctx context.Context) error {
	cfg := config.Get()
	log := zerolog.Ctx(ctx)

	// Create the HTTP(S) server
	s.appSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)),
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Enable HTTP/2 Cleartext
	h2s := &http2.Server{}
	s.appSrv.Handler = h2c.NewHandler(s.appRouter, h2s)

	// Create the listener if we don't have one already
	if s.appListener == nil {
		var err error
		s.appListener, err = net.Listen("tcp", s.appSrv.Addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTP(S) server in a background goroutine
	log.Info().
		Str("bind", cfg.Bind).
		Int("port", cfg.Port).
		Msg("App server started")
	go func() {
		defer s.appListener.Close()

		// Next call blocks until the server is shut down
		srvErr := s.appSrv.Serve(s.appListener)
		if srvErr != http.ErrServerClosed {
			log.Fatal().Err(srvErr).Msgf("Error starting app server")
		}
	}()

	return nil
}

func (s *Server) startMetricsServer(ctx context.Context) error {
	cfg := config.Get()
	log := zerolog.Ctx(ctx)

	// Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.RouteHealthzHandler)
	mux.Handle("/metrics", s.metrics.HTTPHandler())

	// Create the HTTP server
	s.metricsSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.MetricsBind, strconv.Itoa(cfg.MetricsPort)),
		Handler:           mux,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Create the listener if we don't have one already
	if s.metricsListener == nil {
		var err error
		s.metricsListener, err = net.Listen("tcp", s.metricsSrv.Addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTPS server in a background goroutine
	log.Info().
		Str("bind", cfg.MetricsBind).
		Int("port", cfg.MetricsPort).
		Msg("Metrics server started")
	go func() {
		defer s.metricsListener.Close()

		// Next call blocks until the server is shut down
		srvErr := s.metricsSrv.Serve(s.metricsListener)
		if srvErr != http.ErrServerClosed {
			log.Fatal().Err(srvErr).Msgf("Error starting metrics server")
		}
	}()

	return nil
}
