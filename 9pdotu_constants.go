package qp

// VersionDotu is the 9P2000.u version string.
const VersionDotu = "9P2000.u"

// Permissions bits for 9P2000.u.
const (
	DMSYMLINK   FileMode = 0x02000000
	DMLINK      FileMode = 0x01000000
	DMDEVICE    FileMode = 0x00800000
	DMNAMEDPIPE FileMode = 0x00200000
	DMSOCKET    FileMode = 0x00100000
	DMSETUID    FileMode = 0x00080000
	DMSETGID    FileMode = 0x00040000
)

// Qid types for 9P2000.u.
const (
	QTLINK    QidType = 0x01
	QTSYMLINK QidType = 0x02
)
