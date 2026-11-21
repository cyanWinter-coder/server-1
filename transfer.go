// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"time"
)

// newTempPath builds a staging object path next to the target. The name is
// unique per session and per transfer, so a restarted server instance can never
// pick up (or overwrite) the staging data of an earlier transfer.
func (conn *Conn) newTempPath(targetPath string) string {
	var buf [8]byte
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := rand.Read(buf[:]); err == nil {
		suffix += "-" + hex.EncodeToString(buf[:])
	}
	return targetPath + ".goftp-tmp-" + conn.sessionID + "-" + suffix
}

// uploadTransfer streams the data connection into a staging object. The target
// object is only published once the client has finished sending (the data
// connection reached a clean end of stream and the transfer was not
// cancelled): a plain upload renames the complete staging object into place,
// an append/REST upload is staged together with the existing object and then
// renamed. A cancelled or failed transfer removes all staging data and leaves
// the target alone.
func (conn *Conn) uploadTransfer(t *transfer, targetPath string, appendData bool) (int64, error) {
	if t.isCancelled() {
		return 0, errIncompleteTransfer
	}

	tempPath := conn.newTempPath(targetPath)
	conn.logger.Print(conn.sessionID, "Uploading to staging object "+tempPath)
	tempExists := true
	defer func() {
		if tempExists {
			conn.removeTemp(tempPath)
		}
	}()

	bytes, err := conn.driver.PutFile(tempPath, t.data, false)
	if err != nil {
		if t.isCancelled() {
			return bytes, errIncompleteTransfer
		}
		return bytes, err
	}
	if t.isCancelled() {
		// The data socket was closed because the control connection went away
		// (or the drain deadline expired), so the end of stream is not the
		// client's complete upload.
		return bytes, errIncompleteTransfer
	}

	if appendData {
		if err := conn.publishAppend(t, tempPath, targetPath); err != nil {
			return bytes, err
		}
		return bytes, nil
	}

	if err := conn.publishRename(tempPath, targetPath); err != nil {
		return bytes, err
	}
	// The staging object became the target; there is nothing left to remove.
	tempExists = false
	return bytes, nil
}

// publishRename publishes a complete staging object under the target name.
func (conn *Conn) publishRename(tempPath, targetPath string) error {
	return conn.driver.Rename(tempPath, targetPath)
}

// publishAppend publishes an append without ever writing a partial target: the
// existing object and the complete staging object are combined into another
// staging object, which then replaces the target in one rename. When the
// target does not exist yet, the upload itself becomes the target.
func (conn *Conn) publishAppend(t *transfer, tempPath, targetPath string) error {
	if _, err := conn.driver.Stat(targetPath); err != nil {
		// No object to append to: the complete upload is the new target. If
		// the object merely cannot be reached, the rename below fails the
		// same way and the target is left untouched.
		return conn.publishRename(tempPath, targetPath)
	}

	_, existing, err := conn.driver.GetFile(targetPath, 0)
	if err != nil {
		return err
	}
	defer existing.Close()

	_, temp, err := conn.driver.GetFile(tempPath, 0)
	if err != nil {
		return err
	}
	defer temp.Close()

	combinedPath := conn.newTempPath(targetPath)
	combinedExists := true
	defer func() {
		if combinedExists {
			conn.removeTemp(combinedPath)
		}
	}()

	reader := io.MultiReader(existing, temp)
	_, err = conn.driver.PutFile(combinedPath, cancelReader{t: t, r: reader}, false)
	if err != nil {
		if t.isCancelled() {
			return errIncompleteTransfer
		}
		return err
	}
	if t.isCancelled() {
		return errIncompleteTransfer
	}
	if err := conn.publishRename(combinedPath, targetPath); err != nil {
		return err
	}
	combinedExists = false
	return nil
}

// cancelReader stops a driver read once the transfer is cancelled, so an
// append of a large object does not have to run to completion after the drain
// deadline.
type cancelReader struct {
	t *transfer
	r io.Reader
}

func (r cancelReader) Read(p []byte) (int, error) {
	if r.t.isCancelled() {
		return 0, errIncompleteTransfer
	}
	return r.r.Read(p)
}

// removeTemp deletes staging data left over by a failed or cancelled transfer.
func (conn *Conn) removeTemp(tempPath string) {
	// A driver may have failed before creating the staging object at all;
	// there is nothing to report in that case.
	if _, err := conn.driver.Stat(tempPath); err != nil {
		return
	}
	if err := conn.driver.DeleteFile(tempPath); err != nil {
		conn.logger.Printf(conn.sessionID, "failed to remove staging object %s: %v", tempPath, err)
	}
}

// transferErrorText maps a refusal to the FTP reply text that keeps existing
// clients working: a missing or unusable data connection used to be reported
// as "Data connection failed".
func transferErrorText(err error) string {
	switch err {
	case errNoDataConnection, errShuttingDown:
		return "Data connection failed"
	case errTransferInProgress:
		return "Transfer already in progress"
	default:
		return fmt.Sprint(err)
	}
}
