// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// errDataSocketClosed is returned by a data socket once it has been closed,
// either because the transfer completed or because the session went away.
var errDataSocketClosed = errors.New("ftp: data connection closed")

// DataSocket describes a data socket is used to send non-control data between the client and
// server.
type DataSocket interface {
	Host() string

	Port() int

	// the standard io.Reader interface
	Read(p []byte) (n int, err error)

	// the standard io.ReaderFrom interface
	ReadFrom(r io.Reader) (int64, error)

	// the standard io.Writer interface
	Write(p []byte) (n int, err error)

	// the standard io.Closer interface
	Close() error
}

type ftpActiveSocket struct {
	conn      *net.TCPConn
	host      string
	port      int
	logger    Logger
	closeOnce sync.Once
}

func newActiveSocket(remote string, port int, logger Logger, sessionID string) (DataSocket, error) {
	connectTo := net.JoinHostPort(remote, strconv.Itoa(port))

	logger.Print(sessionID, "Opening active data connection to "+connectTo)

	raddr, err := net.ResolveTCPAddr("tcp", connectTo)

	if err != nil {
		logger.Print(sessionID, err)
		return nil, err
	}

	tcpConn, err := net.DialTCP("tcp", nil, raddr)

	if err != nil {
		logger.Print(sessionID, err)
		return nil, err
	}

	socket := new(ftpActiveSocket)
	socket.conn = tcpConn
	socket.host = remote
	socket.port = port
	socket.logger = logger

	return socket, nil
}

func (socket *ftpActiveSocket) Host() string {
	return socket.host
}

func (socket *ftpActiveSocket) Port() int {
	return socket.port
}

func (socket *ftpActiveSocket) Read(p []byte) (n int, err error) {
	return socket.conn.Read(p)
}

func (socket *ftpActiveSocket) ReadFrom(r io.Reader) (int64, error) {
	return socket.conn.ReadFrom(r)
}

func (socket *ftpActiveSocket) Write(p []byte) (n int, err error) {
	return socket.conn.Write(p)
}

func (socket *ftpActiveSocket) Close() error {
	var err error
	socket.closeOnce.Do(func() {
		err = socket.conn.Close()
	})
	return err
}

type ftpPassiveSocket struct {
	conn      net.Conn
	listener  net.Listener
	port      int
	host      string
	logger    Logger
	lock      sync.Mutex // protects conn, listener, err and closed
	err       error
	closed    bool
	ready     chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
	tlsConfig *tls.Config
}

// Detect if an error is "bind: address already in use"
//
// Originally from https://stackoverflow.com/a/52152912/164234
func isErrorAddressAlreadyInUse(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	const WSAEADDRINUSE = 10048
	if runtime.GOOS == "windows" && errErrno == WSAEADDRINUSE {
		return true
	}
	return false
}

func newPassiveSocket(host string, port func() int, logger Logger, sessionID string, tlsConfig *tls.Config) (DataSocket, error) {
	socket := new(ftpPassiveSocket)
	socket.ready = make(chan struct{})
	socket.logger = logger
	socket.host = host
	socket.tlsConfig = tlsConfig
	const retries = 10
	var err error
	for i := 1; i <= retries; i++ {
		socket.port = port()
		err = socket.GoListenAndServe(sessionID)
		if err != nil && socket.port != 0 && isErrorAddressAlreadyInUse(err) {
			// choose a different port on error already in use
			continue
		}
		break
	}
	if err != nil {
		socket.Close()
		return nil, err
	}
	return socket, nil
}

func (socket *ftpPassiveSocket) Host() string {
	return socket.host
}

func (socket *ftpPassiveSocket) Port() int {
	socket.lock.Lock()
	defer socket.lock.Unlock()
	return socket.port
}

// wait blocks until the client has connected to the passive listener (or the
// socket was closed / the accept timed out).
func (socket *ftpPassiveSocket) wait() error {
	<-socket.ready
	socket.lock.Lock()
	defer socket.lock.Unlock()
	if socket.closed {
		return errDataSocketClosed
	}
	if socket.err != nil {
		return socket.err
	}
	return nil
}

func (socket *ftpPassiveSocket) Read(p []byte) (n int, err error) {
	if err := socket.wait(); err != nil {
		return 0, err
	}
	socket.lock.Lock()
	conn := socket.conn
	socket.lock.Unlock()
	if conn == nil {
		return 0, errDataSocketClosed
	}
	// The lock is not held during the read: Close closes the connection to
	// unblock a read that is still in flight.
	return conn.Read(p)
}

func (socket *ftpPassiveSocket) ReadFrom(r io.Reader) (int64, error) {
	if err := socket.wait(); err != nil {
		return 0, err
	}
	socket.lock.Lock()
	conn := socket.conn
	socket.lock.Unlock()
	if conn == nil {
		return 0, errDataSocketClosed
	}

	// For normal TCPConn, this will use sendfile syscall; if not,
	// it will just downgrade to normal read/write procedure
	return io.Copy(conn, r)
}

func (socket *ftpPassiveSocket) Write(p []byte) (n int, err error) {
	if err := socket.wait(); err != nil {
		return 0, err
	}
	socket.lock.Lock()
	conn := socket.conn
	socket.lock.Unlock()
	if conn == nil {
		return 0, errDataSocketClosed
	}
	return conn.Write(p)
}

// Close stops the passive listener and closes the accepted connection, if any.
// It is safe to call repeatedly and from any goroutine; in particular it never
// waits for the accept timeout to expire.
func (socket *ftpPassiveSocket) Close() error {
	var err error
	socket.closeOnce.Do(func() {
		socket.lock.Lock()
		socket.closed = true
		listener := socket.listener
		conn := socket.conn
		socket.conn = nil
		socket.lock.Unlock()

		if listener != nil {
			if cerr := listener.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		if conn != nil {
			if cerr := conn.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		// Unblock any reader waiting for the client to connect. The accept
		// goroutine also closes ready when the listener goes away.
		socket.readyOnce.Do(func() { close(socket.ready) })
	})
	return err
}

func (socket *ftpPassiveSocket) GoListenAndServe(sessionID string) (err error) {
	laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("", strconv.Itoa(socket.port)))
	if err != nil {
		socket.logger.Print(sessionID, err)
		return
	}

	var tcplistener *net.TCPListener
	tcplistener, err = net.ListenTCP("tcp", laddr)
	if err != nil {
		socket.logger.Print(sessionID, err)
		return
	}

	// The timeout, for a remote client to establish connection
	// with a PASV style data connection.
	const acceptTimeout = 60 * time.Second
	err = tcplistener.SetDeadline(time.Now().Add(acceptTimeout))
	if err != nil {
		socket.logger.Print(sessionID, err)
		tcplistener.Close()
		return
	}

	var listener net.Listener = tcplistener
	add := listener.Addr()
	parts := strings.Split(add.String(), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		socket.logger.Print(sessionID, err)
		listener.Close()
		return
	}

	if socket.tlsConfig != nil {
		listener = tls.NewListener(listener, socket.tlsConfig)
	}

	socket.lock.Lock()
	if socket.closed {
		socket.lock.Unlock()
		listener.Close()
		return errDataSocketClosed
	}
	socket.port = port
	socket.listener = listener
	socket.lock.Unlock()

	go socket.accept(listener, sessionID)
	return nil
}

func (socket *ftpPassiveSocket) accept(listener net.Listener, sessionID string) {
	conn, err := listener.Accept()
	// Only one data connection is accepted per PASV/PORT command; release the
	// listening port as soon as the client has connected, or as soon as the
	// accept fails.
	_ = listener.Close()

	if err != nil {
		socket.lock.Lock()
		if socket.closed {
			err = errDataSocketClosed
		}
		socket.err = err
		socket.lock.Unlock()
		socket.readyOnce.Do(func() { close(socket.ready) })
		return
	}

	socket.lock.Lock()
	if socket.closed {
		socket.lock.Unlock()
		conn.Close()
		socket.readyOnce.Do(func() { close(socket.ready) })
		return
	}
	socket.conn = conn
	socket.err = nil
	socket.listener = nil
	socket.lock.Unlock()
	socket.readyOnce.Do(func() { close(socket.ready) })
}
