package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/metrics"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/conditions"
)

// Server is the server based on Gin
type Server struct {
	appRouter  *gin.Engine
	metrics    *metrics.TFAMetrics
	portals    map[string]Portal
	predicates *haxmap.Map[string, cachedPredicate]

	// Servers
	appSrv *http.Server

	// Method that forces a reload of TLS certificates from disk
	tlsCertWatchFn tlsCertWatchFn

	// TLS configuration for the app server
	tlsConfig *tls.Config

	tracer  *sdkTrace.TracerProvider
	running atomic.Bool
	wg      sync.WaitGroup

	// Templates and icons
	templates *template.Template
	icons     map[string]string

	// Server start time, used for Last-Modified headers
	startTime time.Time

	// Listener for the app
	// This can be used for testing without having to start an actual TCP listener
	appListener net.Listener

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server)
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	Log           *slog.Logger
	Metrics       *metrics.TFAMetrics
	TraceExporter sdkTrace.SpanExporter
	Portals       map[string]Portal

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server)
}

// NewServer creates a new Server object and initializes it
func NewServer(opts NewServerOpts) (*Server, error) {
	s := &Server{
		metrics:    opts.Metrics,
		portals:    opts.Portals,
		startTime:  time.Now().UTC(),
		predicates: haxmap.New[string, cachedPredicate](),

		addTestRoutes: opts.addTestRoutes,
	}

	// Init the object
	err := s.init(opts.Log, opts.TraceExporter)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Init the Server object and create a Gin server
func (s *Server) init(log *slog.Logger, traceExporter sdkTrace.SpanExporter) (err error) {
	// Init tracer
	err = s.initTracer(traceExporter)
	if err != nil {
		return err
	}

	// Init the app server
	err = s.initAppServer(log)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initTracer(exporter sdkTrace.SpanExporter) error {
	cfg := config.Get()

	// If tracing is disabled, this is a no-op
	if exporter == nil {
		return nil
	}

	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	s.tracer = sdkTrace.NewTracerProvider(
		sdkTrace.WithResource(resource),
		sdkTrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(s.tracer)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	)

	return nil
}

func (s *Server) initAppServer(log *slog.Logger) (err error) {
	conf := config.Get()

	// Load the TLS configuration
	s.tlsConfig, s.tlsCertWatchFn, err = s.loadTLSConfig(log)
	if err != nil {
		return fmt.Errorf("failed to load TLS configuration: %w", err)
	}

	// Create the Gin router and add various middlewares
	s.appRouter = gin.New()
	s.appRouter.Use(gin.Recovery())
	if s.tracer != nil {
		s.appRouter.Use(otelgin.Middleware("appserver", otelgin.WithTracerProvider(s.tracer)))
	}
	s.appRouter.Use(s.MiddlewareRequestId)
	s.appRouter.Use(s.MiddlewareLogger(log))
	if s.metrics != nil {
		s.appRouter.Use(s.MiddlewareCountMetrics)
	}

	// Register a root route
	s.appRouter.GET("/", serverRootRoute)

	// Logger middleware that removes the auth code from the URL
	codeFilterLogMw := s.MiddlewareLoggerMask(regexp.MustCompile(`(\?|&)(code|state|session_state)=([^&]*)`), "$1$2***")

	// Add static routes & pages
	err = s.addStaticRoutes(conf.Server.BasePath)
	if err != nil {
		return fmt.Errorf("failed to set up static routes: %w", err)
	}
	err = s.loadTemplates(s.appRouter)
	if err != nil {
		return fmt.Errorf("failed to set up pages: %w", err)
	}

	// Healthz route
	// This does not follow BasePath
	s.appRouter.GET("/healthz", gin.WrapF(s.RouteHealthzHandler))

	// Portals
	// If there's a default portal we also register it on the base path, without "portals/:portal"
	registerPortalRoutes := func(r *gin.RouterGroup) {
		// For the root route, we add it with and without trailing slash to avoid Gin setting up a 301 (Permanent) redirect, which causes issues with forward auth
		r.GET("", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.RouteGetAuthRoot)
		r.GET("/", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.RouteGetAuthRoot)
		r.GET("/provider/:provider", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.RouteGetAuthProvider)
		r.GET("/oauth2/callback", codeFilterLogMw, s.RouteGetOAuth2Callback)
		r.GET("/signin", s.RouteGetAuthSignin)
		r.GET("/profile", s.MiddlewareLoadAuthCookie, s.RouteGetProfile)
		r.GET("/profile.json", s.MiddlewareLoadAuthCookie, s.RouteGetProfileJSON)
		r.GET("/logout", s.RouteGetLogout)
	}
	registerPortalRoutes(
		s.appRouter.Group(path.Join(conf.Server.BasePath, "portals/:portal"), s.MiddlewareProxyHeaders),
	)

	if conf.DefaultPortal != "" {
		registerPortalRoutes(
			s.appRouter.Group(conf.Server.BasePath, s.MiddlewareProxyHeaders),
		)
	}

	// API Routes
	// These do not follow BasePath and do not require a client certificate, or loading the auth cookie, or the proxy headers
	apiRoutes := s.appRouter.Group("/api/portals/:portal")
	apiRoutes.GET("/verify", s.RouteGetAPIVerify)

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
			utils.LogFromContext(ctx).WarnContext(ctx,
				"App server shutdown error",
				slog.Any("error", err),
			)
		}
	}()

	// If we have a tlsCertWatchFn, invoke that
	if s.tlsCertWatchFn != nil {
		err = s.tlsCertWatchFn(ctx)
		if err != nil {
			return fmt.Errorf("failed to watch for TLS certificates: %w", err)
		}
	}

	// Periodically clean up the cached predicates
	go s.predicatesCacheCleanup(ctx)

	// Block until the context is canceled
	<-ctx.Done()

	// Servers are stopped with deferred calls
	return nil
}

func (s *Server) predicatesCacheCleanup(ctx context.Context) {
	for {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		select {
		// Exiting
		case <-ctx.Done():
			return

		// Tick
		case <-ticker.C:
			// Clear all cached predicates that haven't been used in over a hour
			before := time.Now().Add(-time.Hour).Unix()
			keys := make([]string, 0)
			for k, v := range s.predicates.Iterator() {
				if v.lastUsed.Load() < before {
					keys = append(keys, k)
				}
			}
			s.predicates.Del(keys...)
		}
	}
}

func (s *Server) startAppServer(ctx context.Context) error {
	cfg := config.Get()
	log := utils.LogFromContext(ctx)

	// Create the HTTP(S) server
	s.appSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Bind, strconv.Itoa(cfg.Server.Port)),
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if s.tlsConfig != nil {
		// Using TLS
		s.appSrv.Handler = s.appRouter
		s.appSrv.TLSConfig = s.tlsConfig
	} else {
		// Not using TLS
		// Here we also need to enable HTTP/2 Cleartext
		h2s := &http2.Server{}
		s.appSrv.Handler = h2c.NewHandler(s.appRouter, h2s)
	}

	// Create the listener if we don't have one already
	if s.appListener == nil {
		var err error
		s.appListener, err = net.Listen("tcp", s.appSrv.Addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTP(S) server in a background goroutine
	log.InfoContext(ctx, "App server started",
		slog.String("bind", cfg.Server.Bind),
		slog.Int("port", cfg.Server.Port),
		slog.Bool("tls", s.tlsConfig != nil),
	)
	go func() {
		defer s.appListener.Close()

		// Next call blocks until the server is shut down
		var srvErr error
		if s.tlsConfig != nil {
			srvErr = s.appSrv.ServeTLS(s.appListener, "", "")
		} else {
			srvErr = s.appSrv.Serve(s.appListener)
		}
		if srvErr != http.ErrServerClosed {
			utils.FatalError(log, "Error starting app server", srvErr)
		}
	}()

	return nil
}

// Loads the TLS configuration
func (s *Server) loadTLSConfig(log *slog.Logger) (tlsConfig *tls.Config, watchFn tlsCertWatchFn, err error) {
	cfg := config.Get()

	tlsConfig = &tls.Config{
		MinVersion: minTLSVersion,
	}

	// If "tlsPath" is empty, use the folder where the config file is located
	tlsPath := cfg.Server.TLSPath
	if tlsPath == "" {
		file := cfg.GetLoadedConfigPath()
		if file != "" {
			tlsPath = filepath.Dir(file)
		}
	}

	// Start by setting the CA certificate and enable mTLS if required
	if cfg.Server.TLSClientAuth {
		// Check if we have the actual keys
		caCert := []byte(cfg.Server.TLSCAPEM)

		// If caCert is empty, we need to load the CA certificate from file
		if len(caCert) > 0 {
			log.Debug("Loaded CA certificate from PEM value")
		} else {
			if tlsPath == "" {
				return nil, nil, errors.New("cannot find a CA certificate, which is required when `tlsClientAuth` is enabled: no path specified in option `tlsPath`, and no config file was loaded")
			}

			caCert, err = os.ReadFile(filepath.Join(tlsPath, tlsCAFile))
			if err != nil {
				// This also returns an error if the file doesn't exist
				// We want to error here as `tlsClientAuth` is true
				return nil, nil, fmt.Errorf("failed to load CA certificate file from path '%s' and 'tlsClientAuth' option is enabled: %w", tlsPath, err)
			}

			log.Debug("Loaded CA certificate from disk", "path", tlsPath)
		}

		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, nil, fmt.Errorf("failed to import CA certificate from PEM found at path '%s'", tlsPath)
		}

		// Set ClientAuth to VerifyClientCertIfGiven because not all endpoints we have require mTLS
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = caCertPool

		log.Debug("TLS Client Authentication is enabled for sensitive endpoints")
	}

	// Let's set the server cert and key now
	// First, check if we have actual keys
	tlsCert := cfg.Server.TLSCertPEM
	tlsKey := cfg.Server.TLSKeyPEM

	// If we don't have actual keys, then we need to load from file and reload when the files change
	if tlsCert == "" && tlsKey == "" {
		if tlsPath == "" {
			// No config file loaded, so don't attempt to load TLS certs
			return nil, nil, nil
		}

		var provider *tlsCertProvider
		provider, err = newTLSCertProvider(tlsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load TLS certificates from path '%s': %w", tlsPath, err)
		}

		// If newTLSCertProvider returns nil, there are no TLS certificates, so disable TLS
		if provider == nil {
			return nil, nil, nil
		}

		log.Debug("Loaded TLS certificates from disk", "path", tlsPath)

		tlsConfig.GetCertificate = provider.GetCertificateFn()

		return tlsConfig, provider.Watch, nil
	}

	// Assume the values from the config file are PEM-encoded certs and key
	if tlsCert == "" || tlsKey == "" {
		// If tlsCert and/or tlsKey is empty, do not use TLS
		return nil, nil, nil
	}

	cert, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse TLS certificate or key: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	log.Debug("Loaded TLS certificates from PEM values")

	return tlsConfig, nil, nil
}

type Portal struct {
	Name                  string
	DisplayName           string
	Providers             map[string]auth.Provider
	ProvidersList         []string
	AuthenticationTimeout time.Duration
	AlwaysShowSigninPage  bool
}

type cachedPredicate struct {
	predicate conditions.UserProfilePredicate
	lastUsed  *atomic.Int64
}

func serverRootRoute(c *gin.Context) {
	// We respond with a 404 status code to prevent people from misconfiguring the forward auth middlewares and getting 200 responses
	c.Status(http.StatusNotFound)
	fmt.Fprint(c.Writer, "👋 traefik-forward-auth is running")
}
