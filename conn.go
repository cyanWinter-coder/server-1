// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultWelcomeMessage = "Welcome to the Go FTP Server"
)

var (
	// errNoDataConnection is returned when a transfer is requested without a
	// PORT/PASV setup.
	errNoDataConnection = errors.New("ftp: no data connection")
	// errTransferInProgress is returned when a second transfer is requested
	// while one is still running on the same session.
	errTransferInProgress = errors.New("ftp: transfer already in progress")
	// errShuttingDown is returned for transfers that were requested after the
	// server started shutting down.
	errShuttingDown = errors.New("ftp: server shutting down")
	// errIncompleteTransfer is returned when the data connection ended with an
	// error, so the uploaded object must not be published.
	errIncompleteTransfer = errors.New("ftp: incomplete data transfer")
)

// transfer owns the data socket of one running command. Transfers run in their
// own goroutine so the command loop stays responsive: a disconnected control
// connection, or the server shutting down, can cancel the transfer without
// touching the other sessions. Only one transfer may run per session.
type transfer struct {
	conn *Conn
	data DataSocket

	cancelOnce sync.Once
	cancelled  chan struct{} // closed when the transfer is cancelled
	done       chan struct{} // closed when the transfer goroutine is done
	doneOnce   sync.Once
}

func newTransfer(conn *Conn, data DataSocket) *transfer {
	return &transfer{
		conn:      conn,
		data:      data,
		cancelled: make(chan struct{}),
		done:      make(chan struct{}),
	}
}

func (t *transfer) cancel() {
	t.cancelOnce.Do(func() {
		if t.cancelled != nil {
			close(t.cancelled)
		}
		if t.data != nil {
			// Closing the socket unblocks whatever read or write is in flight.
			t.data.Close()
		}
	})
}

func (t *transfer) isCancelled() bool {
	select {
	case <-t.cancelled:
		return true
	default:
		return false
	}
}

func (t *transfer) finish() {
	if t.data != nil {
		t.data.Close()
	}
	t.conn.finishTransfer(t)
	t.doneOnce.Do(func() {
		close(t.done)
	})
}

type Conn struct {
	conn          net.Conn
	controlReader *bufio.Reader
	controlWriter *bufio.Writer
	writeMu       sync.Mutex // serialises control responses
	dataConn      DataSocket // pending PORT/PASV socket, not yet transferred
	driver        Driver
	auth          Auth
	logger        Logger
	server        *Server
	tlsConfig     *tls.Config
	sessionID     string
	namePrefix    string
	reqUser       string
	user          string
	renameFrom    string
	lastFilePos   int64
	appendData    bool
	tls           bool

	mu           sync.Mutex // protects the fields below
	closed       bool
	shuttingDown bool
	transfer     *transfer
	drainTimer   *time.Timer
	closeOnce    sync.Once
	transfers    sync.WaitGroup
	cmdQueue     []string // commands read while a transfer was running
	cmdCarry     string   // partial command left over by the transfer watcher
}

func (conn *Conn) LoginUser() string {
	return conn.user
}

func (conn *Conn) IsLogin() bool {
	return len(conn.user) > 0
}

func (conn *Conn) PublicIp() string {
	return conn.server.PublicIp
}

func (conn *Conn) passiveListenIP() string {
	var listenIP string
	if len(conn.PublicIp()) > 0 {
		listenIP = conn.PublicIp()
	} else {
		listenIP = conn.conn.LocalAddr().(*net.TCPAddr).IP.String()
	}

	lastIdx := strings.LastIndex(listenIP, ":")
	if lastIdx <= 0 {
		return listenIP
	}
	return listenIP[:lastIdx]
}

func (conn *Conn) PassivePort() int {
	if len(conn.server.PassivePorts) > 0 {
		portRange := strings.Split(conn.server.PassivePorts, "-")

		if len(portRange) != 2 {
			log.Println("empty port")
			return 0
		}

		minPort, _ := strconv.Atoi(strings.TrimSpace(portRange[0]))
		maxPort, _ := strconv.Atoi(strings.TrimSpace(portRange[1]))

		return minPort + mrand.Intn(maxPort-minPort)
	}
	// let system automatically chose one port
	return 0
}

// returns a random 20 char string that can be used as a unique session ID
func newSessionID() string {
	hash := sha256.New()
	_, err := io.CopyN(hash, rand.Reader, 50)
	if err != nil {
		return "????????????????????"
	}
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	return mdStr[0:20]
}

// Serve starts an endless loop that reads FTP commands from the client and
// responds appropriately. Transfers run in their own goroutine, so the loop
// keeps watching the control connection: if the client disconnects, the
// session's pending data listener and running transfer are cancelled. This
// loop will be running inside a goroutine, so the connection is cleaned up
// when it returns.
func (conn *Conn) Serve() {
	defer func() {
		conn.Close()
		conn.transfers.Wait()
		conn.closeDriver()
		conn.logger.Print(conn.sessionID, "Connection Terminated")
		conn.server.untrackSession(conn)
	}()
	conn.logger.Print(conn.sessionID, "Connection Established")
	// send welcome
	conn.writeMessage(220, conn.server.WelcomeMessage)
	// read commands
	for {
		line, err := conn.nextLine()
		if err != nil {
			if err != io.EOF {
				conn.logger.Print(conn.sessionID, fmt.Sprint("read error:", err))
			}
			break
		}
		conn.receiveLine(line)
		// QUIT command closes connection, break to avoid error on reading from
		// closed socket. The same happens once Shutdown has been requested: the
		// current command (a draining transfer) is the last one.
		if conn.isClosed() || conn.isShuttingDown() {
			break
		}
	}
}

// nextLine returns the next command line. Commands that the transfer watcher
// read from the control connection while a transfer was running are queued and
// handed back here, in order.
func (conn *Conn) nextLine() (string, error) {
	conn.mu.Lock()
	if len(conn.cmdQueue) > 0 {
		line := conn.cmdQueue[0]
		conn.cmdQueue = conn.cmdQueue[1:]
		conn.mu.Unlock()
		return line, nil
	}
	carry := conn.cmdCarry
	conn.cmdCarry = ""
	conn.mu.Unlock()

	line, err := conn.controlReader.ReadString('\n')
	line = carry + line
	if err == nil || strings.HasSuffix(line, "\n") {
		// The read may have been interrupted after a complete command was
		// already buffered (for example by a transfer watcher deadline).
		return line, nil
	}
	if err == io.EOF && line != "" {
		// The client disconnected mid-command; the partial text is not a
		// command.
		conn.logger.Printf(conn.sessionID, "discarding partial command %q", line)
	}
	return "", err
}

func (conn *Conn) isClosed() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closed
}

// Close will manually close this connection, even if the client isn't ready.
// The pending PORT/PASV socket is dropped immediately so its listening port is
// released. A transfer that is still running is cancelled after the drain
// deadline at the latest.
func (conn *Conn) Close() {
	conn.closeOnce.Do(func() {
		conn.mu.Lock()
		conn.closed = true
		dataConn := conn.dataConn
		conn.dataConn = nil
		conn.scheduleDrainLocked()
		conn.mu.Unlock()

		conn.conn.Close()
		if dataConn != nil {
			dataConn.Close()
		}
	})
}

// scheduleDrainLocked arranges for a running transfer to be cancelled when the
// drain deadline expires. conn.mu must be held.
func (conn *Conn) scheduleDrainLocked() {
	t := conn.transfer
	if t == nil || conn.drainTimer != nil {
		return
	}
	conn.drainTimer = time.AfterFunc(conn.drainTimeout(), t.cancel)
}

// drainTimeout is how long a transfer may keep running after the session's
// control connection went away.
func (conn *Conn) drainTimeout() time.Duration {
	if conn.server != nil && conn.server.DrainTimeout > 0 {
		return conn.server.DrainTimeout
	}
	return DefaultShutdownTimeout
}

// beginShutdown is called by Server.Shutdown for every live session. No new
// transfer can start, the control connection is closed (the client is gone for
// good) and idle data sockets are dropped. A transfer that was already running
// is allowed to drain until the session's drain deadline.
func (conn *Conn) beginShutdown() {
	conn.mu.Lock()
	conn.shuttingDown = true
	dataConn := conn.dataConn
	conn.dataConn = nil
	conn.scheduleDrainLocked()
	conn.mu.Unlock()

	if dataConn != nil {
		dataConn.Close()
	}
	// Waking the command loop makes it end the session once the transfer (if
	// any) is over. The control connection closing does not cancel the
	// transfer, so it really gets to drain.
	conn.conn.Close()
}

// forceClose cancels any running transfer and closes the control connection.
// It is used when the drain deadline expires.
func (conn *Conn) forceClose() {
	conn.mu.Lock()
	conn.shuttingDown = true
	t := conn.transfer
	dataConn := conn.dataConn
	conn.dataConn = nil
	conn.mu.Unlock()

	if dataConn != nil {
		dataConn.Close()
	}
	if t != nil {
		t.cancel()
	}
	conn.conn.Close()
}

// beginTransfer takes ownership of the pending data socket, installs a new
// transfer and starts it in its own goroutine. It fails when the session is
// closing, when a transfer is already running or when no data connection was
// set up.
//
// The goroutine always calls t.finish, which releases the socket and lets the
// session know the transfer is over.
func (conn *Conn) beginTransfer() (*transfer, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.shuttingDown || conn.closed {
		return nil, errShuttingDown
	}
	if conn.transfer != nil {
		return nil, errTransferInProgress
	}
	if conn.dataConn == nil {
		return nil, errNoDataConnection
	}
	t := newTransfer(conn, conn.dataConn)
	conn.dataConn = nil
	conn.transfer = t
	return t, nil
}

// start runs the transfer's work in a new goroutine.
func (t *transfer) start(work func() error) {
	t.conn.transfers.Add(1)
	go func() {
		defer t.conn.transfers.Done()
		defer t.finish()
		err := work()
		if err == nil || t.isCancelled() {
			// A cancelled transfer has no client left to answer.
			if err != nil {
				t.conn.logger.Printf(t.conn.sessionID, "transfer cancelled: %v", err)
			}
			return
		}
		t.conn.writeMessage(450, fmt.Sprint("error during transfer: ", err))
	}()
}

// runTransfer starts the transfer work and waits for it. While the transfer
// runs, the control connection is watched: a client disconnect cancels the
// transfer (closing this session's data socket), while commands the client
// sends are queued for the command loop.
func (conn *Conn) runTransfer(t *transfer, work func() error) {
	t.start(work)
	stopWatch := conn.watchControl(t)
	t.wait()
	stopWatch()
}

// watchControl watches the control connection while a transfer is running. An
// EOF means the session is gone, so the transfer is cancelled (during Shutdown
// the server closes the control connection itself; the transfer still drains).
// Commands that arrive in the meantime are consumed and queued, so they are
// still executed once the transfer is over and nothing a client sends is lost.
// The returned function stops the watcher.
func (conn *Conn) watchControl(t *transfer) func() {
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			line, err := conn.controlReader.ReadString('\n')
			if err != nil {
				select {
				case <-stop:
					// The transfer finished first; keep whatever was read so
					// the command loop can finish it.
					if line != "" {
						conn.mu.Lock()
						conn.cmdCarry = line + conn.cmdCarry
						conn.mu.Unlock()
					}
					return
				default:
				}
				// A command may have been cut in half by the read; put the
				// partial text back in front of the next read.
				if line != "" {
					conn.mu.Lock()
					conn.cmdCarry = line
					conn.mu.Unlock()
				}
				if !conn.isShuttingDown() {
					t.cancel()
				}
				return
			}
			conn.queueCommand(line)
		}
	}()

	return func() {
		close(stop)
		// Unblock a read that is still waiting for the client; the command
		// loop restores the deadline before its next read.
		conn.conn.SetReadDeadline(time.Now())
		<-stopped
		conn.conn.SetReadDeadline(time.Time{})
	}
}

func (conn *Conn) queueCommand(line string) {
	if line == "" {
		return
	}
	conn.mu.Lock()
	conn.cmdQueue = append(conn.cmdQueue, line)
	conn.mu.Unlock()
}

// wait blocks until the transfer goroutine has finished.
func (t *transfer) wait() {
	<-t.done
}

// finishTransfer clears the active transfer.
func (conn *Conn) finishTransfer(t *transfer) {
	conn.mu.Lock()
	if conn.transfer == t {
		conn.transfer = nil
	}
	if conn.drainTimer != nil {
		conn.drainTimer.Stop()
		conn.drainTimer = nil
	}
	conn.mu.Unlock()
}

func (conn *Conn) isShuttingDown() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.shuttingDown
}

// closeDriver gives the driver a chance to release per-session resources. It is
// optional so existing drivers keep working unchanged.
func (conn *Conn) closeDriver() {
	if closer, ok := conn.driver.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			conn.logger.Printf(conn.sessionID, "driver close failed: %v", err)
		}
	}
}

// dataConnectionAllowed reports whether the session may still open a new
// PASV/PORT data connection. Once Shutdown has been requested, any new data
// connection is refused.
func (conn *Conn) dataConnectionAllowed() error {
	if conn.server != nil && conn.server.isStopped() {
		return errShuttingDown
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.shuttingDown || conn.closed {
		return errShuttingDown
	}
	return nil
}

// setDataConn installs a freshly opened PORT/PASV socket, replacing (and
// closing) a previous one that was never used. Once Shutdown started, new data
// connections are refused and the socket is closed again immediately.
func (conn *Conn) setDataConn(socket DataSocket) error {
	if err := conn.dataConnectionAllowed(); err != nil {
		socket.Close()
		return err
	}
	conn.mu.Lock()
	if conn.shuttingDown || conn.closed {
		conn.mu.Unlock()
		socket.Close()
		return errShuttingDown
	}
	old := conn.dataConn
	conn.dataConn = socket
	conn.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// pendingDataMatches reports whether the socket already set up by PORT/LPRT
// points at the same host and port, in which case there is no need to dial
// again.
func (conn *Conn) pendingDataMatches(host string, port int) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.dataConn == nil {
		return false
	}
	return conn.dataConn.Host() == host && conn.dataConn.Port() == port
}

func (conn *Conn) upgradeToTLS() error {
	conn.logger.Print(conn.sessionID, "Upgrading connectiion to TLS")
	tlsConn := tls.Server(conn.conn, conn.tlsConfig)
	err := tlsConn.Handshake()
	if err == nil {
		conn.conn = tlsConn
		conn.controlReader = bufio.NewReader(tlsConn)
		conn.controlWriter = bufio.NewWriter(tlsConn)
		conn.tls = true
	}
	return err
}

// receiveLine accepts a single line FTP command and co-ordinates an
// appropriate response.
func (conn *Conn) receiveLine(line string) {
	command, param := conn.parseLine(line)
	conn.logger.PrintCommand(conn.sessionID, command, param)
	cmdObj := commands[strings.ToUpper(command)]
	if cmdObj == nil {
		conn.writeMessage(500, "Command not found")
		return
	}
	if cmdObj.RequireParam() && param == "" {
		conn.writeMessage(553, "action aborted, required param missing")
	} else if cmdObj.RequireAuth() && conn.user == "" {
		conn.writeMessage(530, "not logged in")
	} else {
		cmdObj.Execute(conn, param)
	}
}

func (conn *Conn) parseLine(line string) (string, string) {
	params := strings.SplitN(strings.Trim(line, "\r\n"), " ", 2)
	if len(params) == 1 {
		return params[0], ""
	}
	return params[0], strings.TrimSpace(params[1])
}

// writeMessage will send a standard FTP response back to the client.
func (conn *Conn) writeMessage(code int, message string) (wrote int, err error) {
	conn.logger.PrintResponse(conn.sessionID, code, message)
	line := fmt.Sprintf("%d %s\r\n", code, message)
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	wrote, err = conn.controlWriter.WriteString(line)
	conn.controlWriter.Flush()
	return
}

// writeMessage will send a standard FTP response back to the client.
func (conn *Conn) writeMessageMultiline(code int, message string) (wrote int, err error) {
	conn.logger.PrintResponse(conn.sessionID, code, message)
	line := fmt.Sprintf("%d-%s\r\n%d END\r\n", code, message, code)
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	wrote, err = conn.controlWriter.WriteString(line)
	conn.controlWriter.Flush()
	return
}

// buildPath takes a client supplied path or filename and generates a safe
// absolute path within their account sandbox.
//
//	buildpath("/")
//	=> "/"
//	buildpath("one.txt")
//	=> "/one.txt"
//	buildpath("/files/two.txt")
//	=> "/files/two.txt"
//	buildpath("files/two.txt")
//	=> "/files/two.txt"
//	buildpath("/../../../../etc/passwd")
//	=> "/etc/passwd"
//
// The driver implementation is responsible for deciding how to treat this path.
// Obviously they MUST NOT just read the path off disk. The probably want to
// prefix the path with something to scope the users access to a sandbox.
func (conn *Conn) buildPath(filename string) (fullPath string) {
	if len(filename) > 0 && filename[0:1] == "/" {
		fullPath = filepath.Clean(filename)
	} else if len(filename) > 0 && filename != "-a" {
		fullPath = filepath.Clean(conn.namePrefix + "/" + filename)
	} else {
		fullPath = filepath.Clean(conn.namePrefix)
	}
	fullPath = strings.Replace(fullPath, "//", "/", -1)
	fullPath = strings.Replace(fullPath, string(filepath.Separator), "/", -1)
	return
}

// sendOutofbandData sends a string to the client via the transfer's data
// socket and reports the bytes sent with a 226 reply. The caller has already
// taken the data socket through beginTransfer and must run the transfer.
func (conn *Conn) sendOutofbandData(t *transfer, data []byte) error {
	bytes := len(data)
	conn.runTransfer(t, func() error {
		if _, err := t.data.Write(data); err != nil {
			return errIncompleteTransfer
		}
		message := "Closing data connection, sent " + strconv.Itoa(bytes) + " bytes"
		conn.writeMessage(226, message)
		return nil
	})
	return nil
}
