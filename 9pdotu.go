package qp

import "encoding/binary"

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

func (s *StatDotu) UnmarshalBinary(b []byte) error {
	t := 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4
	if len(b) < t {
		return ErrPayloadTooShort
	}

	// Well then, let's get started...
	s.Type = binary.LittleEndian.Uint16(b[2:4])
	s.Dev = binary.LittleEndian.Uint32(b[4:8])

	// Decode the qid
	s.Qid.Type = QidType(b[8])
	s.Qid.Version = binary.LittleEndian.Uint32(b[9:13])
	s.Qid.Path = binary.LittleEndian.Uint64(b[13:21])

	// More of the main struct
	s.Mode = FileMode(binary.LittleEndian.Uint32(b[21:25]))
	s.Atime = binary.LittleEndian.Uint32(b[25:29])
	s.Mtime = binary.LittleEndian.Uint32(b[29:33])
	s.Length = binary.LittleEndian.Uint64(b[33:41])

	// And now the variable part.

	// Name
	idx := 41
	l := int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	if len(b) < t+l {
		return ErrPayloadTooShort
	}
	s.Name = string(b[idx+2 : idx+2+l])
	idx += 2 + l
	t += l

	// UID
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	if len(b) < t+int(l) {
		return ErrPayloadTooShort
	}
	s.UID = string(b[idx+2 : idx+2+l])
	idx += 2 + l
	t += l

	// GID
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	if len(b) < t+l {
		return ErrPayloadTooShort
	}
	s.GID = string(b[idx+2 : idx+2+l])
	idx += 2 + l
	t += l

	// MUID
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	if len(b) < t+l {
		return ErrPayloadTooShort
	}
	s.MUID = string(b[idx+2 : idx+2+l])
	idx += 2 + l
	t += l

	// Extensions
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	if len(b) < t+l {
		return ErrPayloadTooShort
	}
	s.Extensions = string(b[idx+2 : idx+2+l])
	idx += 2 + l

	// UIDno, GIDno, MUIDno
	s.UIDno = binary.LittleEndian.Uint32(b[idx : idx+4])
	s.GIDno = binary.LittleEndian.Uint32(b[idx+4 : idx+8])
	s.MUIDno = binary.LittleEndian.Uint32(b[idx+8 : idx+12])
	return nil
}

func (s *StatDotu) MarshalBinary() ([]byte, error) {
	l := 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4 + len(s.Name) + len(s.UID) + len(s.GID) + len(s.MUID) + len(s.Extensions)
	b := make([]byte, l)
	binary.LittleEndian.PutUint16(b[0:2], uint16(l-2))
	binary.LittleEndian.PutUint16(b[2:4], s.Type)
	binary.LittleEndian.PutUint32(b[4:8], s.Dev)

	// Qid
	b[8] = byte(s.Qid.Type)
	binary.LittleEndian.PutUint32(b[9:13], s.Qid.Version)
	binary.LittleEndian.PutUint64(b[13:21], s.Qid.Path)
	binary.LittleEndian.PutUint32(b[21:25], uint32(s.Mode))
	binary.LittleEndian.PutUint32(b[25:29], s.Atime)
	binary.LittleEndian.PutUint32(b[29:33], s.Mtime)
	binary.LittleEndian.PutUint64(b[33:41], s.Length)

	// Variable things
	// Name
	idx := 41
	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(s.Name)))
	idx += 2
	copy(b[idx:], []byte(s.Name))
	idx += len(s.Name)

	// UID
	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(s.UID)))
	idx += 2
	copy(b[idx:], []byte(s.UID))
	idx += len(s.UID)

	// GID
	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(s.GID)))
	idx += 2
	copy(b[idx:], []byte(s.GID))
	idx += len(s.GID)

	// MUID
	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(s.MUID)))
	idx += 2
	copy(b[idx:], []byte(s.MUID))
	idx += len(s.MUID)

	// Extensions
	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(s.Extensions)))
	idx += 2
	copy(b[idx:], []byte(s.Extensions))
	idx += len(s.Extensions)

	// UIDno, GIDno, MUIDno
	binary.LittleEndian.PutUint32(b[idx:idx+4], s.UIDno)
	binary.LittleEndian.PutUint32(b[idx+4:idx+8], s.GIDno)
	binary.LittleEndian.PutUint32(b[idx+8:idx+12], s.MUIDno)
	return b, nil
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

func (ar *AuthRequestDotu) UnmarshalBinary(b []byte) error {
	t := 2 + 4 + 2 + 2 + 4
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	ar.AuthFid = Fid(binary.LittleEndian.Uint32(b[2:6]))

	l := int(binary.LittleEndian.Uint16(b[6:8]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Username = string(b[8 : 8+l])

	idx := 8 + l
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Service = string(b[idx+2 : idx+2+l])

	ar.UIDno = binary.LittleEndian.Uint32(b[idx+2+l : idx+2+l+4])
	return nil
}

func (ar *AuthRequestDotu) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+4+2+len(ar.Username)+2+len(ar.Service)+4)
	binary.LittleEndian.PutUint16(b[0:2], uint16(ar.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(ar.AuthFid))

	binary.LittleEndian.PutUint16(b[6:8], uint16(len(ar.Username)))
	copy(b[8:], []byte(ar.Username))
	idx := 8 + len(ar.Username)

	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(ar.Service)))
	copy(b[idx+2:], []byte(ar.Service))
	idx += 2 + len(ar.Service)
	binary.LittleEndian.PutUint32(b[idx:idx+4], ar.UIDno)
	return b, nil
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

func (ar *AttachRequestDotu) UnmarshalBinary(b []byte) error {
	t := 2 + 4 + 4 + 2 + 2 + 4
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	ar.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	ar.AuthFid = Fid(binary.LittleEndian.Uint32(b[6:10]))

	l := int(binary.LittleEndian.Uint16(b[10:12]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Username = string(b[12 : 12+l])

	idx := 12 + l
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Service = string(b[idx+2 : idx+2+l])

	ar.UIDno = binary.LittleEndian.Uint32(b[idx+2+l : idx+2+l+4])
	return nil
}

func (ar *AttachRequestDotu) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+4+4+2+len(ar.Username)+2+len(ar.Service)+4)
	binary.LittleEndian.PutUint16(b[0:2], uint16(ar.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(ar.Fid))
	binary.LittleEndian.PutUint32(b[6:10], uint32(ar.AuthFid))

	binary.LittleEndian.PutUint16(b[10:12], uint16(len(ar.Username)))
	copy(b[12:], []byte(ar.Username))
	idx := 12 + len(ar.Username)

	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(ar.Service)))
	copy(b[idx+2:], []byte(ar.Service))
	idx += 2 + len(ar.Service)
	binary.LittleEndian.PutUint32(b[idx:idx+4], ar.UIDno)
	return b, nil
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

func (er *ErrorResponseDotu) UnmarshalBinary(b []byte) error {
	t := 2 + 2 + 4
	if len(b) < t {
		return ErrPayloadTooShort
	}
	er.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))

	l := int(binary.LittleEndian.Uint16(b[2:4]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	er.Error = string(b[4 : 4+l])

	er.Errno = binary.LittleEndian.Uint32(b[4+l : 4+l+4])
	return nil
}

func (er *ErrorResponseDotu) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+2+len(er.Error)+4)
	binary.LittleEndian.PutUint16(b[0:2], uint16(er.Tag))
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(er.Error)))
	copy(b[4:], []byte(er.Error))
	idx := 4 + len(er.Error)
	binary.LittleEndian.PutUint32(b[idx:idx+4], er.Errno)
	return b, nil
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

func (cr *CreateRequestDotu) UnmarshalBinary(b []byte) error {
	t := 2 + 4 + 2 + 4 + 1 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}
	cr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	cr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))

	l := int(binary.LittleEndian.Uint16(b[6:8]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}

	idx := 8
	cr.Name = string(b[idx : idx+l])
	idx += l

	cr.Permissions = FileMode(binary.LittleEndian.Uint32(b[idx : idx+4]))
	cr.Mode = OpenMode(b[idx+4])

	idx += 5
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	cr.Extensions = string(b[idx+2 : idx+2+l])
	return nil
}

func (cr *CreateRequestDotu) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+4+2+len(cr.Name)+4+1+2+len(cr.Extensions))
	binary.LittleEndian.PutUint16(b[0:2], uint16(cr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(cr.Fid))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(cr.Name)))

	idx := 8
	copy(b[idx:idx+len(cr.Name)], []byte(cr.Name))
	idx += len(cr.Name)

	binary.LittleEndian.PutUint32(b[idx:idx+4], uint32(cr.Permissions))
	b[idx+4] = byte(cr.Mode)
	idx += 5

	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(cr.Extensions)))
	copy(b[idx+2:], []byte(cr.Extensions))
	return b, nil
}

// StatResponseDotu is the 9P2000.u version of StatResponse. It uses a
// different stat struct, StatDotu.
type StatResponseDotu struct {
	Tag

	// Stat is the requested StatDotu struct.
	Stat StatDotu
}

func (sr *StatResponseDotu) UnmarshalBinary(b []byte) error {
	if len(b) < 2+2 {
		return ErrPayloadTooShort
	}

	sr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	return sr.Stat.UnmarshalBinary(b[4:])
}

func (sr *StatResponseDotu) MarshalBinary() ([]byte, error) {
	x, err := sr.Stat.MarshalBinary()
	if err != nil {
		return nil, err
	}

	b := make([]byte, 2+2+len(x))
	binary.LittleEndian.PutUint16(b[0:2], uint16(sr.Tag))
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(x)))
	copy(b[4:], x)
	return b, nil
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

func (wsr *WriteStatRequestDotu) UnmarshalBinary(b []byte) error {
	if len(b) < 2+4+2 {
		return ErrPayloadTooShort
	}

	wsr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	wsr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	return wsr.Stat.UnmarshalBinary(b[8:])
}

func (wsr *WriteStatRequestDotu) MarshalBinary() ([]byte, error) {
	x, err := wsr.Stat.MarshalBinary()
	if err != nil {
		return nil, err
	}

	b := make([]byte, 2+4+2+len(x))
	binary.LittleEndian.PutUint16(b[0:2], uint16(wsr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(wsr.Fid))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(x)))
	copy(b[8:], x)
	return b, nil
}
