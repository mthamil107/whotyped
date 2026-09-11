//go:build linux

package auditd

import (
	"errors"
	"net"
)

// errUnsupported is never returned on Linux; declared so socket.go stays portable.
var errUnsupported = errors.New("auditd: unsupported")

// dialAudisp connects to the audisp af_unix plugin socket.
func dialAudisp(path string) (net.Conn, error) {
	return net.Dial("unix", path)
}
