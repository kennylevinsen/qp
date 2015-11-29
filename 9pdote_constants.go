package qp

// VersionDote is the 9P2000.e version string.
const VersionDote = "9P2000.e"

// MessageType constants for 9P2000.e.
const (
	Tsession MessageType = 150 + iota
	Rsession
	Tsread
	Rsread
	Tswrite
	Rswrite
)
