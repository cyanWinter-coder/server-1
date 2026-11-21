// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// DefaultShutdownTimeout bounds how long Shutdown waits for transfers that
// were already running when the server was asked to stop.
const DefaultShutdownTimeout = 5 * time.Second

// Version returns the library version
func Version() string {
	return "0.3.0"
}

// ServerOpts contains parameters for server.NewServer()
type ServerOpts struct {
	// The factory that will be used to create a new FTPDriver instance for
	// each client connection. This is a mandatory option.
	Factory DriverFactory

	Auth Auth

	// Server Name, Default is Go Ftp Server
	Name string

	// The hostname that the FTP server should listen on. Optional, defaults to
	// "::", which means all hostnames on ipv4 and ipv6.
	Hostname string

	// Public IP of the server
	PublicIp string

	// Passive ports
	PassivePorts string

	// The port that the FTP should listen on. Optional, defaults to 3000. In
	// a production environment you will probably want to change this to 21.
	Port int

	// use tls, default is false
	TLS bool

	// if tls used, cert file is required
	CertFile string

	// if tls used, key file is required
	KeyFile string

	// If ture TLS is used in RFC4217 mode
	ExplicitFTPS bool

	WelcomeMessage string

	// A logger implementation, if nil the StdLogger is used
	Logger Logger

	// ShutdownTimeout bounds how long Shutdown waits for transfers that were
	// already in progress when it was called. Transfers that do not finish
	// within the deadline are closed and their temporary data is removed.
	// Defaults to DefaultShutdownTimeout.
	ShutdownTimeout time.Duration

	// DrainTimeout bounds how long a session whose control connection went
	// away may keep an already running transfer alive. When the deadline
	// expires the transfer is cancelled and its temporary data is removed.
	// Defaults to DefaultShutdownTimeout.
	DrainTimeout time.Duration
}

// Server is the root of your FTP application. You should instantiate one
// of these and call ListenAndServe() to start accepting client connections.
//
// Always use the NewServer() method to create a new Server.
type Server struct {
	*ServerOpts
	listenTo  string
	logger    Logger
	listener  net.Listener
	tlsConfig *tls.Config
	ctx       context.Context
	cancel    context.CancelFunc
	feats     string

	// lifecycle protects ctx, cancel, listener and the session set. It is
	// also what makes Shutdown safe to call more than once, concurrently.
	lifecycle    sync.Mutex
	started      bool
	stopped      bool
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	sessions     map[*Conn]struct{}
	sessionsDone sync.WaitGroup
}

// ErrServerClosed is returned by ListenAndServe() or Serve() when a shutdown
// was requested.
var ErrServerClosed = errors.New("ftp: Server closed")

// serverOptsWithDefaults copies an ServerOpts struct into a new struct,
// then adds any default values that are missing and returns the new data.
func serverOptsWithDefaults(opts *ServerOpts) *ServerOpts {
	var newOpts ServerOpts
	if opts == nil {
		opts = &ServerOpts{}
	}
	if opts.Hostname == "" {
		newOpts.Hostname = "::"
	} else {
		newOpts.Hostname = opts.Hostname
	}
	if opts.Port == 0 {
		newOpts.Port = 3000
	} else {
		newOpts.Port = opts.Port
	}
	newOpts.Factory = opts.Factory
	if opts.Name == "" {
		newOpts.Name = "Go FTP Server"
	} else {
		newOpts.Name = opts.Name
	}

	if opts.WelcomeMessage == "" {
		newOpts.WelcomeMessage = defaultWelcomeMessage
	} else {
		newOpts.WelcomeMessage = opts.WelcomeMessage
	}

	if opts.Auth != nil {
		newOpts.Auth = opts.Auth
	}

	newOpts.Logger = &StdLogger{}
	if opts.Logger != nil {
		newOpts.Logger = opts.Logger
	}

	newOpts.TLS = opts.TLS
	newOpts.KeyFile = opts.KeyFile
	newOpts.CertFile = opts.CertFile
	newOpts.ExplicitFTPS = opts.ExplicitFTPS

	newOpts.PublicIp = opts.PublicIp
	newOpts.PassivePorts = opts.PassivePorts

	newOpts.ShutdownTimeout = opts.ShutdownTimeout
	if newOpts.ShutdownTimeout <= 0 {
		newOpts.ShutdownTimeout = DefaultShutdownTimeout
	}
	newOpts.DrainTimeout = opts.DrainTimeout
	if newOpts.DrainTimeout <= 0 {
		newOpts.DrainTimeout = DefaultShutdownTimeout
	}

	return &newOpts
}

// NewServer initialises a new FTP server. Configuration options are provided
// via an instance of ServerOpts. Calling this function in your code will
// probably look something like this:
//
//	factory := &MyDriverFactory{}
//	server  := server.NewServer(&server.ServerOpts{ Factory: factory })
//
// or:
//
//	factory := &MyDriverFactory{}
//	opts    := &server.ServerOpts{
//	  Factory: factory,
//	  Port: 2000,
//	  Hostname: "127.0.0.1",
//	}
//	server  := server.NewServer(opts)
func NewServer(opts *ServerOpts) *Server {
	opts = serverOptsWithDefaults(opts)
	s := new(Server)
	s.ServerOpts = opts
	s.listenTo = net.JoinHostPort(opts.Hostname, strconv.Itoa(opts.Port))
	s.logger = opts.Logger
	s.sessions = make(map[*Conn]struct{})
	return s
}

// NewConn constructs a new object that will handle the FTP protocol over
// an active net.TCPConn. The TCP connection should already be open before
// it is handed to this functions. driver is an instance of FTPDriver that
// will handle all auth and persistence details.
func (server *Server) newConn(tcpConn net.Conn, driver Driver) *Conn {
	c := new(Conn)
	c.namePrefix = "/"
	c.conn = tcpConn
	c.controlReader = bufio.NewReader(tcpConn)
	c.controlWriter = bufio.NewWriter(tcpConn)
	c.driver = driver
	c.auth = server.Auth
	c.server = server
	c.sessionID = newSessionID()
	c.logger = server.logger
	c.tlsConfig = server.tlsConfig

	driver.Init(c)
	return c
}

func simpleTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	config := &tls.Config{}
	if config.NextProtos == nil {
		config.NextProtos = []string{"ftp"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// ListenAndServe asks a new Server to begin accepting client connections. It
// accepts no arguments - all configuration is provided via the NewServer
// function.
//
// If the server fails to start for any reason, an error will be returned. Common
// errors are trying to bind to a privileged port or something else is already
// listening on the same port.
func (server *Server) ListenAndServe() error {
	var listener net.Listener
	var err error
	var curFeats = featCmds

	if server.ServerOpts.TLS {
		server.tlsConfig, err = simpleTLSConfig(server.CertFile, server.KeyFile)
		if err != nil {
			return err
		}

		curFeats += " AUTH TLS\n PBSZ\n PROT\n"

		if server.ServerOpts.ExplicitFTPS {
			listener, err = net.Listen("tcp", server.listenTo)
		} else {
			listener, err = tls.Listen("tcp", server.listenTo, server.tlsConfig)
		}
	} else {
		listener, err = net.Listen("tcp", server.listenTo)
	}
	if err != nil {
		return err
	}
	server.feats = fmt.Sprintf(feats, curFeats)

	sessionID := ""
	server.logger.Printf(sessionID, "%s listening on %d", server.Name, server.Port)

	return server.Serve(listener)
}

// Serve accepts connections on a given net.Listener and handles each
// request in a new goroutine.
func (server *Server) Serve(l net.Listener) error {
	ctx, cancel := context.WithCancel(context.Background())
	server.lifecycle.Lock()
	if server.stopped {
		server.lifecycle.Unlock()
		cancel()
		l.Close()
		return ErrServerClosed
	}
	server.listener = l
	server.ctx, server.cancel = ctx, cancel
	server.started = true
	server.lifecycle.Unlock()
	defer cancel()

	sessionID := ""
	for {
		tcpConn, err := server.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ErrServerClosed
			default:
			}
			server.logger.Printf(sessionID, "listening error: %v", err)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		driver, err := server.Factory.NewDriver()
		if err != nil {
			server.logger.Printf(sessionID, "Error creating driver, aborting client connection: %v", err)
			tcpConn.Close()
			continue
		}
		ftpConn := server.newConn(tcpConn, driver)
		if !server.trackSession(ftpConn) {
			// Shutdown has already closed the listener, but a connection can
			// still have been accepted in the race window.
			ftpConn.Close()
			ftpConn.closeDriver()
			return ErrServerClosed
		}
		go ftpConn.Serve()
	}
}

// trackSession registers a control connection so Shutdown can wait for it.
// It reports false once the server is shutting down.
func (server *Server) trackSession(conn *Conn) bool {
	server.lifecycle.Lock()
	defer server.lifecycle.Unlock()
	if server.stopped || !server.started {
		return false
	}
	if server.sessions == nil {
		server.sessions = make(map[*Conn]struct{})
	}
	server.sessions[conn] = struct{}{}
	server.sessionsDone.Add(1)
	return true
}

// untrackSession removes a control connection and signals that its goroutine
// has finished cleaning up.
func (server *Server) untrackSession(conn *Conn) {
	server.lifecycle.Lock()
	if _, ok := server.sessions[conn]; ok {
		delete(server.sessions, conn)
		server.sessionsDone.Done()
	}
	server.lifecycle.Unlock()
}

// currentSessions returns a snapshot of the live control connections.
func (server *Server) currentSessions() []*Conn {
	server.lifecycle.Lock()
	defer server.lifecycle.Unlock()
	conns := make([]*Conn, 0, len(server.sessions))
	for conn := range server.sessions {
		conns = append(conns, conn)
	}
	return conns
}

// Shutdown will gracefully stop a server. No new control connections are
// accepted and no new PASV/PORT data connection can be opened. Sessions with a
// transfer already running are drained until the drain deadline; sessions
// without one stop immediately. Transfers that do not finish in time are
// cancelled and their temporary objects removed. Shutdown returns once every
// session goroutine and data listener has been cleaned up.
//
// Shutdown is safe to call concurrently: the shutdown is broadcast once, and
// every caller observes the same result.
func (server *Server) Shutdown() error {
	server.lifecycle.Lock()
	if server.shutdownDone == nil {
		server.shutdownDone = make(chan struct{})
	}
	done := server.shutdownDone
	server.lifecycle.Unlock()

	server.shutdownOnce.Do(func() {
		go func() {
			defer close(done)
			server.shutdown()
		}()
	})
	<-done
	return nil
}

func (server *Server) shutdown() {
	server.lifecycle.Lock()
	server.stopped = true
	cancel := server.cancel
	listener := server.listener
	server.lifecycle.Unlock()

	if cancel != nil {
		cancel()
	}
	if listener != nil {
		// ErrServerClosed is reported by Serve; closing the listener is an
		// expected part of shutting down and is not a failure here.
		listener.Close()
	}

	// Refuse new data connections and drop pending ones. Sessions with an
	// active transfer keep it (the transfer owns its data socket) and drain.
	sessions := server.currentSessions()
	for _, conn := range sessions {
		conn.beginShutdown()
	}

	deadline := time.NewTimer(server.drainDeadline())
	defer deadline.Stop()

	drained := make(chan struct{})
	go func() {
		server.sessionsDone.Wait()
		close(drained)
	}()

	select {
	case <-drained:
	case <-deadline.C:
		// The drain period is over: cancel the remaining transfers so their
		// goroutines remove temporary data, then wait for the cleanup.
		for _, conn := range server.currentSessions() {
			conn.forceClose()
		}
		<-drained
	}
}

// drainDeadline is how long Shutdown lets in-flight transfers finish.
func (server *Server) drainDeadline() time.Duration {
	if server.ShutdownTimeout > 0 {
		return server.ShutdownTimeout
	}
	return DefaultShutdownTimeout
}

// isStopped reports whether Shutdown has been requested.
func (server *Server) isStopped() bool {
	server.lifecycle.Lock()
	defer server.lifecycle.Unlock()
	return server.stopped
}
