package qp

import "io"

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

// Decode decodes a stream into the message.
func (s *StatDotu) Decode(r io.Reader) error {
	var err error

	// We have no use of this length
	if _, err = readUint16(r); err != nil {
		return err
	}
	if s.Type, err = readUint16(r); err != nil {
		return err
	}
	if s.Dev, err = readUint32(r); err != nil {
		return err
	}
	if err = s.Qid.Decode(r); err != nil {
		return err
	}
	if s.Mode, err = readFileMode(r); err != nil {
		return err
	}
	if s.Atime, err = readUint32(r); err != nil {
		return err
	}
	if s.Mtime, err = readUint32(r); err != nil {
		return err
	}
	if s.Length, err = readUint64(r); err != nil {
		return err
	}
	if s.Name, err = readString(r); err != nil {
		return err
	}
	if s.UID, err = readString(r); err != nil {
		return err
	}
	if s.GID, err = readString(r); err != nil {
		return err
	}
	if s.MUID, err = readString(r); err != nil {
		return err
	}
	if s.Extensions, err = readString(r); err != nil {
		return err
	}
	if s.UIDno, err = readUint32(r); err != nil {
		return err
	}
	if s.GIDno, err = readUint32(r); err != nil {
		return err
	}
	if s.MUIDno, err = readUint32(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (s *StatDotu) Encode(w io.Writer) error {
	var err error

	l := uint16(s.EncodedLength() - 2)

	if err = writeUint16(w, l); err != nil {
		return err
	}
	if err = writeUint16(w, s.Type); err != nil {
		return err
	}
	if err = writeUint32(w, s.Dev); err != nil {
		return err
	}
	if err = s.Qid.Encode(w); err != nil {
		return err
	}
	if err = writeFileMode(w, s.Mode); err != nil {
		return err
	}
	if err = writeUint32(w, s.Atime); err != nil {
		return err
	}
	if err = writeUint32(w, s.Mtime); err != nil {
		return err
	}
	if err = writeUint64(w, s.Length); err != nil {
		return err
	}
	if err = writeString(w, s.Name); err != nil {
		return err
	}
	if err = writeString(w, s.UID); err != nil {
		return err
	}
	if err = writeString(w, s.GID); err != nil {
		return err
	}
	if err = writeString(w, s.MUID); err != nil {
		return err
	}
	if err = writeString(w, s.Extensions); err != nil {
		return err
	}
	if err = writeUint32(w, s.UIDno); err != nil {
		return err
	}
	if err = writeUint32(w, s.GIDno); err != nil {
		return err
	}
	if err = writeUint32(w, s.MUIDno); err != nil {
		return err
	}
	return nil

}

// AuthRequestDotu is the 9P2000.u version of AuthRequestDotu. It adds UIDno,
// for compatibility with platforms that use numeric user IDs. UIDno takes
// precedence over Username.
type AuthRequestDotu struct {
	Tag Tag

	// AuthFid is the fid to be used for authentication
	AuthFid Fid

	// Username is the user to authenticate as.
	Username string

	// Service is the service to authenticate access to.
	Service string

	// UIDno is a UID number for platforms using numeric user IDs.
	UIDno uint32
}

// GetTag retrieves the current tag.
func (ar *AuthRequestDotu) GetTag() Tag {
	return ar.Tag
}

// SetTag assigns the current tag.
func (ar *AuthRequestDotu) SetTag(t Tag) {
	ar.Tag = t
}

// EncodedLength returns the length the message will be when serialized.
func (ar *AuthRequestDotu) EncodedLength() int {
	return 2 + 4 + 2 + len(ar.Username) + 2 + len(ar.Service) + 4
}

// Decode decodes a stream into the message.
func (ar *AuthRequestDotu) Decode(r io.Reader) error {
	var err error
	if ar.Tag, err = readTag(r); err != nil {
		return err
	}
	if ar.AuthFid, err = readFid(r); err != nil {
		return err
	}
	if ar.Username, err = readString(r); err != nil {
		return err
	}
	if ar.Service, err = readString(r); err != nil {
		return err
	}
	if ar.UIDno, err = readUint32(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (ar *AuthRequestDotu) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, ar.Tag); err != nil {
		return err
	}
	if err = writeFid(w, ar.AuthFid); err != nil {
		return err
	}
	if err = writeString(w, ar.Username); err != nil {
		return err
	}
	if err = writeString(w, ar.Service); err != nil {
		return err
	}
	if err = writeUint32(w, ar.UIDno); err != nil {
		return err
	}
	return nil
}

// AttachRequestDotu is the 9P2000.u version of AttachRequestDotu. It adds
// UIDno, for compatibility with platforms that use numeric user IDs. UIDno
// takes precedence over Username.
type AttachRequestDotu struct {
	Tag Tag

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

// GetTag retrieves the current tag.
func (ar *AttachRequestDotu) GetTag() Tag {
	return ar.Tag
}

// SetTag assigns the current tag.
func (ar *AttachRequestDotu) SetTag(t Tag) {
	ar.Tag = t
}

// EncodedLength returns the length the message will be when serialized.
func (ar *AttachRequestDotu) EncodedLength() int {
	return 2 + 4 + 4 + 2 + len(ar.Username) + 2 + len(ar.Service) + 4
}

// Decode decodes a stream into the message.
func (ar *AttachRequestDotu) Decode(r io.Reader) error {
	var err error
	if ar.Tag, err = readTag(r); err != nil {
		return err
	}
	if ar.Fid, err = readFid(r); err != nil {
		return err
	}
	if ar.AuthFid, err = readFid(r); err != nil {
		return err
	}
	if ar.Username, err = readString(r); err != nil {
		return err
	}
	if ar.Service, err = readString(r); err != nil {
		return err
	}
	if ar.UIDno, err = readUint32(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (ar *AttachRequestDotu) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, ar.Tag); err != nil {
		return err
	}
	if err = writeFid(w, ar.Fid); err != nil {
		return err
	}
	if err = writeFid(w, ar.AuthFid); err != nil {
		return err
	}
	if err = writeString(w, ar.Username); err != nil {
		return err
	}
	if err = writeString(w, ar.Service); err != nil {
		return err
	}
	if err = writeUint32(w, ar.UIDno); err != nil {
		return err
	}
	return nil
}

// ErrorResponseDotu is the 9P2000.u version of ErrorResponse. It adds Errno
// in an attempt to improve compatibility with platforms that use numeric
// errors. Errno takes precedence over Error.
type ErrorResponseDotu struct {
	Tag Tag

	// Error is the error string.
	Error string

	// Errno is the error code.
	Errno uint32
}

// GetTag retrieves the current tag.
func (er *ErrorResponseDotu) GetTag() Tag {
	return er.Tag
}

// SetTag assigns the current tag.
func (er *ErrorResponseDotu) SetTag(t Tag) {
	er.Tag = t
}

// EncodedLength returns the length the message will be when serialized.
func (er *ErrorResponseDotu) EncodedLength() int {
	return 2 + 2 + len(er.Error) + 4
}

// Decode decodes a stream into the message.
func (er *ErrorResponseDotu) Decode(r io.Reader) error {
	var err error
	if er.Tag, err = readTag(r); err != nil {
		return err
	}
	if er.Error, err = readString(r); err != nil {
		return err
	}
	if er.Errno, err = readUint32(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (er *ErrorResponseDotu) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, er.Tag); err != nil {
		return err
	}
	if err = writeString(w, er.Error); err != nil {
		return err
	}
	if err = writeUint32(w, er.Errno); err != nil {
		return err
	}
	return nil
}

// CreateRequestDotu is the 9P2000.u version of CreateRequest. It adds
// Extensions, describing special files on platforms that use them.
type CreateRequestDotu struct {
	Tag Tag

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

// GetTag retrieves the current tag.
func (cr *CreateRequestDotu) GetTag() Tag {
	return cr.Tag
}

// SetTag assigns the current tag.
func (cr *CreateRequestDotu) SetTag(t Tag) {
	cr.Tag = t
}

// EncodedLength returns the length the message will be when serialized.
func (cr *CreateRequestDotu) EncodedLength() int {
	return 2 + 4 + 2 + len(cr.Name) + 4 + 1 + 2 + len(cr.Extensions)
}

// Decode decodes a stream into the message.
func (cr *CreateRequestDotu) Decode(r io.Reader) error {
	var err error
	if cr.Tag, err = readTag(r); err != nil {
		return err
	}
	if cr.Fid, err = readFid(r); err != nil {
		return err
	}
	if cr.Name, err = readString(r); err != nil {
		return err
	}
	if cr.Permissions, err = readFileMode(r); err != nil {
		return err
	}
	if cr.Mode, err = readOpenMode(r); err != nil {
		return err
	}
	if cr.Extensions, err = readString(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (cr *CreateRequestDotu) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, cr.Tag); err != nil {
		return err
	}
	if err = writeFid(w, cr.Fid); err != nil {
		return err
	}
	if err = writeString(w, cr.Name); err != nil {
		return err
	}
	if err = writeFileMode(w, cr.Permissions); err != nil {
		return err
	}
	if err = writeOpenMode(w, cr.Mode); err != nil {
		return err
	}
	if err = writeString(w, cr.Extensions); err != nil {
		return err
	}
	return nil
}

// StatResponseDotu is the 9P2000.u version of StatResponse. It uses a
// different stat struct, StatDotu.
type StatResponseDotu struct {
	Tag Tag

	// Stat is the requested StatDotu struct.
	Stat StatDotu
}

// GetTag retrieves the current tag.
func (sr *StatResponseDotu) GetTag() Tag {
	return sr.Tag
}

// SetTag assigns the current tag.
func (sr *StatResponseDotu) SetTag(t Tag) {
	sr.Tag = t
}

// EncodedLength returns the length the message will be when serialized.
func (sr *StatResponseDotu) EncodedLength() int {
	return 2 + 2 + sr.Stat.EncodedLength()
}

// Decode decodes a stream into the message.
func (sr *StatResponseDotu) Decode(r io.Reader) error {
	var err error
	if sr.Tag, err = readTag(r); err != nil {
		return err
	}

	// We don't need this
	if _, err = readUint16(r); err != nil {
		return err
	}

	if err = sr.Stat.Decode(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (sr *StatResponseDotu) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, sr.Tag); err != nil {
		return err
	}

	if err = writeUint16(w, uint16(sr.Stat.EncodedLength())); err != nil {
		return err
	}

	if err = sr.Stat.Encode(w); err != nil {
		return err
	}

	return nil
}

// WriteStatRequestDotu is the 9P2000.u version of WriteStatRequest. It uses a
// different stat struct, StatDotu.
type WriteStatRequestDotu struct {
	Tag Tag

	// Fid is the file to modify the Stat struct for.
	Fid Fid

	// Stat is the StatDotu struct to apply.
	Stat StatDotu
}

// GetTag retrieves the current tag.
func (wsr *WriteStatRequestDotu) GetTag() Tag {
	return wsr.Tag
}

// SetTag assigns the current tag.
func (wsr *WriteStatRequestDotu) SetTag(t Tag) {
	wsr.Tag = t
}

// EncodedLength returns the length the message will be when serialized.
func (wsr *WriteStatRequestDotu) EncodedLength() int {
	return 2 + 4 + 2 + wsr.Stat.EncodedLength()
}

// Decode decodes a stream into the message.
func (wsr *WriteStatRequestDotu) Decode(r io.Reader) error {
	var err error
	if wsr.Tag, err = readTag(r); err != nil {
		return err
	}
	if wsr.Fid, err = readFid(r); err != nil {
		return err
	}

	// We don't need the stat size
	if _, err = readUint16(r); err != nil {
		return err
	}

	if err = wsr.Stat.Decode(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (wsr *WriteStatRequestDotu) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, wsr.Tag); err != nil {
		return err
	}
	if err = writeFid(w, wsr.Fid); err != nil {
		return err
	}
	if err = writeUint16(w, uint16(wsr.Stat.EncodedLength())); err != nil {
		return err
	}
	if err = wsr.Stat.Encode(w); err != nil {
		return err
	}
	return nil
}
