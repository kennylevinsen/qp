package qp

// NineP2000Dotu implements 9P2000.u encoding and decoding. 9P2000.u is meant
// as a unix compatibility extension. 9P is designed for Plan9, and as thus
// send many things as strings rather than numeric codes, such as user IDs and
// error codes. It also does not provide any "special file" functionality, as
// is often used on unix systems. 9P2000.u adds an extra set of numeric IDs to
// those messages, in parallel with their already existing string variant. It
// should be noted that these numeric IDs are highly platform and
// configuration dependent, and not portable by any definition of the term.
//
// Message types
//
// 9P2000.u replaces the following messages:
// 	ErrorResponseDotu:    size[4] Rerror tag[2] ename[s] errno[4]
// 	AuthRequestDotu:      size[4] Tauth tag[2] afid[4] uname[s] aname[s]
// 	AttachRequestDotu:    size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
// 	CreateRequestDotu:    size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1] extension[s]
// 	StatResponseDotu:     size[4] Rstat tag[2] stat[n]
// 	WriteStatRequestDotu: size[4] Twstat tag[2] fid[4] stat[n]
//
// Support structures
//
// 9P2000.u replaces the following supporting structures:
//    StatDotu: size[2] type[2] dev[4] qid[13] mode[4] atime[4] mtime[4] length[8]
//                  name[s] uid[s] gid[s] muid[s] extensions[s] nuid[4] ngid[4] nmuid[4]
var NineP2000Dotu Protocol = &Codec{
	M2MT: MessageToMessageTypeDotu,
	MT2M: MessageTypeToMessageDotu,
}

// StatDotu is the 9P2000.u version of the Stat struct. It adds Extensions,
// UIDno, GIDno and MUIDno fields in an attempt to improve compatibility with
// platforms using special files and numeric user IDs. UIDno, GIDno and MUIDno
// takes precedence over UID, GID and MUID.
type StatDotu struct {
	// Type is reserved for kernel use.
	Type uint16

	// Dev is reserved for kernel use.
	Dev uint32

	// Qid is the Qid for the file.
	Qid Qid

	// Mode is the permissions and mode of the file.
	Mode FileMode

	// Atime is the last access time of the file.
	Atime uint32

	// Mtime is the last modification time of the file.
	Mtime uint32

	// Length is the length of the file, commonly 0 for directories.
	Length uint64

	// Name is the name of the file.
	Name string

	// UID is the username of the owning user.
	UID string

	// GID is the group name of the owning group.
	GID string

	// MUID is the user who last modified the file.
	MUID string

	// Extensions is used to store data about special files.
	Extensions string

	// UIDno is a UID number for platforms using numeric user IDs.
	UIDno uint32

	// GIDno is a GID number for platforms using numeric user IDs.
	GIDno uint32

	// MUIDno is a MUID number for platforms using numeric user IDs.
	MUIDno uint32
}

// EncodedLength returns the length the message will be when serialized.
func (s *StatDotu) EncodedLength() int {
	return 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 8 + len(s.Name) + len(s.UID) + len(s.GID) + len(s.MUID) + 2 + len(s.Extensions) + 4 + 4 + 4
}

// AuthRequestDotu is the 9P2000.u version of AuthRequestDotu. It adds UIDno,
// for compatibility with platforms that use numeric user IDs. UIDno takes
// precedence over Username.
type AuthRequestDotu struct {
	Tag

	// AuthFid is the fid to be used for authentication
	AuthFid Fid

	// Username is the user to authenticate as.
	Username string

	// Service is the service to authenticate access to.
	Service string

	// UIDno is a UID number for platforms using numeric user IDs.
	UIDno uint32
}

// EncodedLength returns the length the message will be when serialized.
func (ar *AuthRequestDotu) EncodedLength() int {
	return 2 + 4 + 2 + len(ar.Username) + 2 + len(ar.Service) + 4
}

// AttachRequestDotu is the 9P2000.u version of AttachRequestDotu. It adds
// UIDno, for compatibility with platforms that use numeric user IDs. UIDno
// takes precedence over Username.
type AttachRequestDotu struct {
	Tag

	// Fid is the fid that will be assigned the root node.
	Fid Fid

	// AuthFid is the fid of the previously executed authentication protocol, or
	// NOFID if the service does not need authentication.
	AuthFid Fid

	// Username is the user the connection will operate as.
	Username string

	// Service is the service that will be accessed.
	Service string

	// UIDno is a UID number for platforms using numeric user IDs.
	UIDno uint32
}

// EncodedLength returns the length the message will be when serialized.
func (ar *AttachRequestDotu) EncodedLength() int {
	return 2 + 4 + 4 + 2 + len(ar.Username) + 2 + len(ar.Service) + 4
}

// ErrorResponseDotu is the 9P2000.u version of ErrorResponse. It adds Errno
// in an attempt to improve compatibility with platforms that use numeric
// errors. Errno takes precedence over Error.
type ErrorResponseDotu struct {
	Tag

	// Error is the error string.
	Error string

	// Errno is the error code.
	Errno uint32
}

// EncodedLength returns the length the message will be when serialized.
func (er *ErrorResponseDotu) EncodedLength() int {
	return 2 + 2 + len(er.Error) + 4
}

// CreateRequestDotu is the 9P2000.u version of CreateRequest. It adds
// Extensions, describing special files on platforms that use them.
type CreateRequestDotu struct {
	Tag

	// Fid is the fid of the directory where the file should be created, but
	// upon successful creation and opening, it changes to the opened file.
	Fid Fid

	// Name is the name of the file to create.
	Name string

	// Permissions are the permissions and mode of the file to create.
	Permissions FileMode

	// Mode is the mode the file should be opened under.
	Mode OpenMode

	// Extensions describe special files.
	Extensions string
}

// EncodedLength returns the length the message will be when serialized.
func (cr *CreateRequestDotu) EncodedLength() int {
	return 2 + 4 + 2 + len(cr.Name) + 4 + 1 + 2 + len(cr.Extensions)
}

// StatResponseDotu is the 9P2000.u version of StatResponse. It uses a
// different stat struct, StatDotu.
type StatResponseDotu struct {
	Tag

	// Stat is the requested StatDotu struct.
	Stat StatDotu
}

// EncodedLength returns the length the message will be when serialized.
func (sr *StatResponseDotu) EncodedLength() int {
	return 2 + 2 + sr.Stat.EncodedLength()
}

// WriteStatRequestDotu is the 9P2000.u version of WriteStatRequest. It uses a
// different stat struct, StatDotu.
type WriteStatRequestDotu struct {
	Tag

	// Fid is the file to modify the Stat struct for.
	Fid Fid

	// Stat is the StatDotu struct to apply.
	Stat StatDotu
}

// EncodedLength returns the length the message will be when serialized.
func (wsr *WriteStatRequestDotu) EncodedLength() int {
	return 2 + 4 + 2 + wsr.Stat.EncodedLength()
}
