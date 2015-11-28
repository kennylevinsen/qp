package qp

const (
	// HeaderSize is the overhead of the size and type fields of the 9P2000
	// header.
	HeaderSize = 4 + 1
)

const (
	// Version is the 9P2000 version string.
	Version = "9P2000"

	// UnknownVersion is used to indicate failed version negotiation.
	UnknownVersion = "unknown"
)

// MessageType constants
const (
	Tversion MessageType = 100 + iota
	Rversion
	Tauth
	Rauth
	Tattach
	Rattach
	Terror // Not a valid message
	Rerror
	Tflush
	Rflush
	Twalk
	Rwalk
	Topen
	Ropen
	Tcreate
	Rcreate
	Tread
	Rread
	Twrite
	Rwrite
	Tclunk
	Rclunk
	Tremove
	Rremove
	Tstat
	Rstat
	Twstat
	Rwstat
)

// Special message values
const (
	NOTAG Tag = 0xFFFF
	NOFID Fid = 0xFFFFFFFF
)

// Opening modes
const (
	OREAD OpenMode = iota
	OWRITE
	ORDWR
	OEXEC

	OTRUNC OpenMode = 16 * (iota + 1)
	OCEXEC
	ORCLOSE
)

// Permission bits
const (
	DMDIR    FileMode = 0x80000000
	DMAPPEND FileMode = 0x40000000
	DMEXCL   FileMode = 0x20000000
	DMMOUNT  FileMode = 0x10000000
	DMAUTH   FileMode = 0x08000000
	DMTMP    FileMode = 0x04000000
	DMREAD   FileMode = 0x4
	DMWRITE  FileMode = 0x2
	DMEXEC   FileMode = 0x1
)

// Qid types
const (
	QTFILE   QidType = 0x00
	QTTMP    QidType = 0x04
	QTAUTH   QidType = 0x08
	QTMOUNT  QidType = 0x10
	QTEXCL   QidType = 0x20
	QTAPPEND QidType = 0x40
	QTDIR    QidType = 0x80
)
