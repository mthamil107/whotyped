//go:build !linux

package auditd

import (
	"net"

	"github.com/mthamil107/whotyped/internal/readers"
)

// errUnsupported makes SocketSource.Run return ErrUnsupportedPlatform.
var errUnsupported = readers.ErrUnsupportedPlatform

// dialAudisp: there is no audisp socket off Linux.
func dialAudisp(string) (net.Conn, error) {
	return nil, readers.ErrUnsupportedPlatform
}
