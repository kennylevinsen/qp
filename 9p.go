package qp

import "encoding/binary"

// NineP2000 implements 9P2000 encoding and decoding.
//
// Message types
//
// 9P2000 defines the following messages:
//
// 	VersionRequest:    size[4] Tversion tag[2] msize[4] version[s]
// 	VersionResponse:   size[4] Rversion tag[2] msize[4] version[s]
// 	AuthRequest:       size[4] Tauth tag[2] afid[4] uname[s] aname[s]
// 	AuthResponse:      size[4] Rauth tag[2] aqid[13]
// 	AttachRequest:     size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
// 	AttachResponse:    size[4] Rattach tag[2] qid[13]
// 	ErrorResponse:     size[4] Rerror tag[2] ename[s]
// 	FlushRequest:      size[4] Tflush tag[2] oldtag[2]
// 	FlushResponse:     size[4] Rflush tag[2]
// 	WalkRequest:       size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
// 	WalkResponse:      size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
// 	OpenRequest:       size[4] Topen tag[2] fid[4] mode[1]
// 	OpenResponse:      size[4] Ropen tag[2] qid[13] iounit[4]
// 	CreateRequest:     size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1]
// 	CreateResponse:    size[4] Rcreate tag[2] qid[13] iounit[4]
// 	ReadRequest:       size[4] Tread tag[2] fid[4] offset[8] count[4]
// 	ReadResponse:      size[4] Rread tag[2] count[4] data[count]
// 	WriteRequest:      size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
// 	WriteResponse:     size[4] Rwrite tag[2] count[4]
// 	ClunkRequest:      size[4] Tclunk tag[2] fid[4]
// 	ClunkResponse:     size[4] Rclunk tag[2]
// 	RemoveRequest:     size[4] Tremove tag[2] fid[4]
// 	RemoveResponse:    size[4] Rremove tag[2]
// 	StatRequest:       size[4] Tstat tag[2] fid[4]
// 	StatResponse:      size[4] Rstat tag[2] stat[n]
// 	WriteStatRequest:  size[4] Twstat tag[2] fid[4] stat[n]
// 	WriteStatResponse: size[4] Rwstat tag[2]
//
// Support structures
//
// 9P2000 defines the following supporting structures:
//    Qid:  type[1] version[4] path[8]
//    Stat: size[2] type[2] dev[4] qid[13] mode[4] atime[4] mtime[4] length[8]
//              name[s] uid[s] gid[s] muid[s]
var NineP2000 = nineP2000{}

// Tag is a unique identifier for a request. It is echoed by the response. It
// is the responsibility of the client to ensure that it is unique among all
// current requests.
type Tag uint16

// GetTag is a convenience method to retrieve the tag without type asserting.
func (t Tag) GetTag() Tag {
	return t
}

// Fid is a "file identifier", and is quite similar in concept to a file
// descriptor, and is used to keep track of a file and its potential opening
// mode. The client is responsible for providing a unique Fid to use. The Fid
// is passed to all later requests to inform the server what file the
// manipulation should occur on. Multiple Fids can be open on a connection.
// Fids are local to the connection, and can be reused after Remove or Clunk.
type Fid uint32

// OpenMode represents the opening mode of a file, such as read, write or
// execute.
type OpenMode byte

// FileMode is the mode and permissions of a file.
type FileMode uint32

// QidType specifies the filetype in Qid structs, such as a regular file,
// directory or auth.
type QidType byte

// Qid is a unique file identification from the server.
type Qid struct {
	Type QidType

	// Version describes the version of the file. It is usually incremented
	// every time the file is changed.
	Version uint32

	// Path is a unique identifier for the file within a file server.
	Path uint64
}

func (q *Qid) EncodedSize() int { return 13 }

func (q *Qid) Marshal(b []byte) error {
	b[0] = byte(q.Type)
	binary.LittleEndian.PutUint32(b[1:5], q.Version)
	binary.LittleEndian.PutUint64(b[5:13], q.Path)
	return nil
}

func (q *Qid) Unmarshal(b []byte) error {
	if len(b) < 13 {
		return ErrPayloadTooShort
	}
	q.Type = QidType(b[0])
	q.Version = binary.LittleEndian.Uint32(b[1:5])
	q.Path = binary.LittleEndian.Uint64(b[5:13])
	return nil
}

// Stat is a directory entry, providing detailed information of a file. It is
// called "Dir" in many other implementations.
type Stat struct {
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
}

func (s *Stat) EncodedSize() int {
	return 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2 + len(s.Name) + len(s.UID) + len(s.GID) + len(s.MUID)
}

func (s *Stat) Marshal(b []byte) error {
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

	// Length prefix
	binary.LittleEndian.PutUint16(b[0:2], uint16(idx-2))
	return nil
}

func (s *Stat) Unmarshal(b []byte) error {
	t := 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2
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
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	s.Name = string(b[idx+2 : idx+2+l])
	idx += 2 + l

	// UID
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t+l {
		return ErrPayloadTooShort
	}
	s.UID = string(b[idx+2 : idx+2+l])
	idx += 2 + l

	// GID
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	s.GID = string(b[idx+2 : idx+2+l])
	idx += 2 + l

	// MUID
	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	s.MUID = string(b[idx+2 : idx+2+l])

	return nil
}

//
// Message type structs and the encode/decode methods below.
//

// VersionRequest is used to inform the server of the maximum size it intends
// to send or it can receive, as well as the maximum protocol version
// supported. The tag used for this request must be NOTAG.
type VersionRequest struct {
	Tag

	// MessageSize is the suggested absolute maximum message size for the
	// connection. The final negotiated value must be honoured. This field is
	// called "msize" in the official implementation.
	MessageSize uint32

	// Version is the suggested maximum protocol version for the connection.
	Version string
}

func (vr *VersionRequest) EncodedSize() int {
	return 2 + 4 + 2 + len(vr.Version)
}

func (vr *VersionRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(vr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(vr.MessageSize))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(vr.Version)))
	copy(b[8:], []byte(vr.Version))
	return nil
}

func (vr *VersionRequest) Unmarshal(b []byte) error {
	t := 2 + 4 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}
	vr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	vr.MessageSize = binary.LittleEndian.Uint32(b[2:6])

	idx := 6
	l := int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	vr.Version = string(b[idx+2 : idx+2+l])

	return nil
}

// VersionResponse is used to inform the client of maximum size and version,
// taking the clients VersionRequest into consideration. MessageSize in the
// reply must not be larger than MessageSize in the request, and the version
// must likewise be equal to or lower than the one in the requst.
type VersionResponse struct {
	Tag

	// MessageSize is the negotiated maximum message size for the connection.
	// This value must be honoured. This field is called "msize" in the
	// official implementation.
	MessageSize uint32

	// Version is the negotiated protocol version, or "unknown" if negotiation
	// failed.
	Version string
}

func (vr *VersionResponse) EncodedSize() int { return 2 + 4 + 2 + len(vr.Version) }

func (vr *VersionResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(vr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(vr.MessageSize))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(vr.Version)))
	copy(b[8:], []byte(vr.Version))
	return nil
}

func (vr *VersionResponse) Unmarshal(b []byte) error {
	t := 2 + 4 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}
	vr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	vr.MessageSize = binary.LittleEndian.Uint32(b[2:6])

	idx := 6
	l := int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	vr.Version = string(b[idx+2 : idx+2+l])

	return nil
}

// AuthRequest is used to request and authentication protocol connection from
// the server. The AuthFid can be used to read/write the authentication
//  The protocol itself is not part of 9P2000.
type AuthRequest struct {
	Tag

	// AuthFid is the fid to be used for authentication. This field is called
	// "afid" in the official implementation.
	AuthFid Fid

	// Username is the user to authenticate as. This field is called "uname" in
	// the official implementation.
	Username string

	// Service is the service to authenticate access to. This field is called
	// "aname" in the official implementation.
	Service string
}

func (ar *AuthRequest) EncodedSize() int {
	return 2 + 4 + 2 + len(ar.Username) + 2 + len(ar.Service)
}

func (ar *AuthRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(ar.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(ar.AuthFid))

	idx := 6
	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(ar.Username)))
	copy(b[idx+2:], []byte(ar.Username))
	idx += 2 + len(ar.Username)

	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(ar.Service)))
	copy(b[idx+2:], []byte(ar.Service))
	return nil
}

func (ar *AuthRequest) Unmarshal(b []byte) error {
	t := 2 + 4 + 2 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	ar.AuthFid = Fid(binary.LittleEndian.Uint32(b[2:6]))

	idx := 6
	l := int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Username = string(b[idx+2 : idx+2+l])
	idx += 2 + l

	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Service = string(b[idx+2 : idx+2+l])

	return nil
}

// AuthResponse is used to acknowledge the authentication protocol connection,
// and to return the matching Qid.
type AuthResponse struct {
	Tag

	// AuthQid is the Qid representing the special authentication file. This
	// field is called "aqid" in the official implementation.
	AuthQid Qid
}

func (ar *AuthResponse) EncodedSize() int { return 2 + 13 }

func (ar *AuthResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(ar.Tag))
	b[2] = byte(ar.AuthQid.Type)
	binary.LittleEndian.PutUint32(b[3:7], ar.AuthQid.Version)
	binary.LittleEndian.PutUint64(b[7:15], ar.AuthQid.Path)
	return nil
}

func (ar *AuthResponse) Unmarshal(b []byte) error {
	if len(b) < 2+13 {
		return ErrPayloadTooShort
	}

	ar.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	ar.AuthQid.Type = QidType(b[2])
	ar.AuthQid.Version = binary.LittleEndian.Uint32(b[3:7])
	ar.AuthQid.Path = binary.LittleEndian.Uint64(b[7:15])
	return nil
}

// AttachRequest is used to establish a connection to a service as a user, and
// attach a fid to the root of the service.
type AttachRequest struct {
	Tag

	// Fid is the fid that will be assigned the root node.
	Fid Fid

	// AuthFid is the fid of the previously executed authentication protocol,
	// or NOFID if the service does not need authentication. This field is
	// called "afid" in the official implementation.
	AuthFid Fid

	// Username is the user the connection will operate as. This field is
	// called "uname" in the official implementation.
	Username string

	// Service is the service that will be accessed. This field is called
	// "aname" in the official implementation.
	Service string
}

func (ar *AttachRequest) EncodedSize() int {
	return 2 + 4 + 4 + 2 + len(ar.Username) + 2 + len(ar.Service)
}

func (ar *AttachRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(ar.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(ar.Fid))
	binary.LittleEndian.PutUint32(b[6:10], uint32(ar.AuthFid))

	idx := 10
	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(ar.Username)))
	copy(b[idx+2:], []byte(ar.Username))
	idx += 2 + len(ar.Username)

	binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(len(ar.Service)))
	copy(b[idx+2:], []byte(ar.Service))
	return nil
}

func (ar *AttachRequest) Unmarshal(b []byte) error {
	t := 2 + 4 + 4 + 2 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	ar.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	ar.AuthFid = Fid(binary.LittleEndian.Uint32(b[6:10]))

	idx := 10
	l := int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Username = string(b[idx+2 : idx+2+l])
	idx += 2 + l

	l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
	t += l
	if len(b) < t {
		return ErrPayloadTooShort
	}
	ar.Service = string(b[idx+2 : idx+2+l])

	return nil
}

// AttachResponse acknowledges an attach.
type AttachResponse struct {
	Tag

	// Qid is the qid of the root node.
	Qid Qid
}

func (ar *AttachResponse) EncodedSize() int { return 2 + 13 }

func (ar *AttachResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(ar.Tag))
	b[2] = byte(ar.Qid.Type)
	binary.LittleEndian.PutUint32(b[3:7], ar.Qid.Version)
	binary.LittleEndian.PutUint64(b[7:15], ar.Qid.Path)
	return nil
}

func (ar *AttachResponse) Unmarshal(b []byte) error {
	if len(b) < 2+13 {
		return ErrPayloadTooShort
	}

	ar.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	ar.Qid.Type = QidType(b[2])
	ar.Qid.Version = binary.LittleEndian.Uint32(b[3:7])
	ar.Qid.Path = binary.LittleEndian.Uint64(b[7:15])
	return nil
}

// ErrorResponse is used when the server wants to report and error with the
// request. There is no ErrorRequest, as such a thing would not make sense.
type ErrorResponse struct {
	Tag

	// Error is the error string. This field is called "ename" in the official
	// implementation.
	Error string
}

func (er *ErrorResponse) EncodedSize() int { return 2 + 2 + len(er.Error) }

func (er *ErrorResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(er.Tag))
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(er.Error)))
	copy(b[4:], []byte(er.Error))
	return nil
}

func (er *ErrorResponse) Unmarshal(b []byte) error {
	t := 2 + 2
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

	return nil
}

// FlushRequest is used to cancel a pending request. The flushed tag can be
// used after a response have been received.
type FlushRequest struct {
	Tag

	// OldTag is the tag of the request to cancel.
	OldTag Tag
}

func (fr *FlushRequest) EncodedSize() int { return 2 + 2 }

func (fr *FlushRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(fr.Tag))
	binary.LittleEndian.PutUint16(b[2:4], uint16(fr.OldTag))
	return nil
}

func (fr *FlushRequest) Unmarshal(b []byte) error {
	if len(b) < 2+2 {
		return ErrPayloadTooShort
	}
	fr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	fr.OldTag = Tag(binary.LittleEndian.Uint16(b[2:4]))
	return nil
}

// FlushResponse is used to indicate a successful flush. Do note that
// FlushResponse have a peculiar behaviour when multiple flushes are pending.
type FlushResponse struct {
	Tag
}

func (fr *FlushResponse) EncodedSize() int { return 2 }

func (fr *FlushResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(fr.Tag))
	return nil
}

func (fr *FlushResponse) Unmarshal(b []byte) error {
	if len(b) < 2 {
		return ErrPayloadTooShort
	}
	fr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	return nil
}

// WalkRequest is used to walk into directories, starting from the current fid.
// All but the last name must be directories. If the walk succeeds, the file is
// assigned to NewFid.
type WalkRequest struct {
	Tag

	// Fid is the fid to walk from.
	Fid Fid

	// NewFid is the fid to assign the successful walk to.
	NewFid Fid

	// Names are the names to try.
	Names []string
}

func (wr *WalkRequest) EncodedSize() int {
	l := 2 + 4 + 4 + 2
	for i := range wr.Names {
		l += 2 + len(wr.Names[i])
	}

	return l
}

func (wr *WalkRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(wr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(wr.Fid))
	binary.LittleEndian.PutUint32(b[6:10], uint32(wr.NewFid))
	binary.LittleEndian.PutUint16(b[10:12], uint16(len(wr.Names)))
	idx := 12
	for i := range wr.Names {
		l := len(wr.Names[i])
		binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(l))
		copy(b[idx+2:], []byte(wr.Names[i]))
		idx += 2 + l
	}
	return nil
}

func (wr *WalkRequest) Unmarshal(b []byte) error {
	t := 2 + 4 + 4 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}
	wr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	wr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	wr.NewFid = Fid(binary.LittleEndian.Uint32(b[6:10]))

	l := int(binary.LittleEndian.Uint16(b[10:12]))
	idx := 12
	wr.Names = make([]string, l)
	for i := range wr.Names {
		if len(b) < t+2 {
			return ErrPayloadTooShort
		}

		l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
		if len(b) < t+2+l {
			return ErrPayloadTooShort
		}
		wr.Names[i] = string(b[idx+2 : idx+2+l])
		idx += 2 + l
		t += 2 + l
	}
	return nil
}

// WalkResponse returns the qids for each successfully walked element. If the
// walk is successful, the amount of qids will be identical to the amount of
// names.
type WalkResponse struct {
	Tag

	// Qids are the qids for the successfully walked files.
	Qids []Qid
}

func (wr *WalkResponse) EncodedSize() int { return 2 + 2 + 13*len(wr.Qids) }

func (wr *WalkResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(wr.Tag))
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(wr.Qids)))
	idx := 4
	for i := range wr.Qids {
		b[idx] = byte(wr.Qids[i].Type)
		binary.LittleEndian.PutUint32(b[idx+1:idx+5], wr.Qids[i].Version)
		binary.LittleEndian.PutUint64(b[idx+5:idx+13], wr.Qids[i].Path)
		idx += 13
	}
	return nil
}

func (wr *WalkResponse) Unmarshal(b []byte) error {
	t := 2 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}

	wr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	l := int(binary.LittleEndian.Uint16(b[2:4]))
	t += l * 13
	if len(b) < t {
		return ErrPayloadTooShort
	}
	wr.Qids = make([]Qid, l)
	idx := 4
	for i := range wr.Qids {
		wr.Qids[i].Type = QidType(b[idx])
		wr.Qids[i].Version = binary.LittleEndian.Uint32(b[idx+1 : idx+5])
		wr.Qids[i].Path = binary.LittleEndian.Uint64(b[idx+5 : idx+13])
	}
	return nil
}

// OpenRequest is used to open a fid for reading/writing/executing.
type OpenRequest struct {
	Tag

	// Fid is the file to open.
	Fid Fid

	// Mode is the mode to open file under.
	Mode OpenMode
}

func (or *OpenRequest) EncodedSize() int { return 2 + 4 + 1 }

func (or *OpenRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(or.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(or.Fid))
	b[6] = byte(or.Mode)
	return nil
}

func (or *OpenRequest) Unmarshal(b []byte) error {
	if len(b) < 2+4+1 {
		return ErrPayloadTooShort
	}

	or.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	or.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	or.Mode = OpenMode(b[6])
	return nil
}

// OpenResponse returns the qid of the file, as well as iounit, which is a
// read/write size that is guaranteed to be successfully written/read, or 0
// for no such guarantee.
type OpenResponse struct {
	Tag

	// Qid is the qid of the opened file.
	Qid Qid

	// IOUnit is the maximum amount of data that can be read/written by a single
	// call, or 0 for no specification.
	IOUnit uint32
}

func (or *OpenResponse) EncodedSize() int { return 2 + 13 + 4 }

func (or *OpenResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(or.Tag))
	b[2] = byte(or.Qid.Type)
	binary.LittleEndian.PutUint32(b[3:7], or.Qid.Version)
	binary.LittleEndian.PutUint64(b[7:15], or.Qid.Path)
	binary.LittleEndian.PutUint32(b[15:19], or.IOUnit)
	return nil
}

func (or *OpenResponse) Unmarshal(b []byte) error {
	if len(b) < 2+13+4 {
		return ErrPayloadTooShort
	}

	or.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	or.Qid.Type = QidType(b[2])
	or.Qid.Version = binary.LittleEndian.Uint32(b[3:7])
	or.Qid.Path = binary.LittleEndian.Uint64(b[7:15])
	or.IOUnit = binary.LittleEndian.Uint32(b[15:19])
	return nil
}

// CreateRequest tries to create a file in the current directory with the
// provided permissions, and then open it with behaviour identical to
// OpenRequest. A directory is created by creating a file with the DMDIR
// permission bit set.
type CreateRequest struct {
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
}

func (cr *CreateRequest) EncodedSize() int { return 2 + 4 + 2 + len(cr.Name) + 4 + 1 }

func (cr *CreateRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(cr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(cr.Fid))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(cr.Name)))

	idx := 8
	copy(b[idx:idx+len(cr.Name)], []byte(cr.Name))
	idx += len(cr.Name)

	binary.LittleEndian.PutUint32(b[idx:idx+4], uint32(cr.Permissions))
	b[idx+4] = byte(cr.Mode)
	return nil
}

func (cr *CreateRequest) Unmarshal(b []byte) error {
	t := 2 + 4 + 2 + 4 + 1
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

	cr.Name = string(b[8 : 8+l])
	idx := 8 + l
	cr.Permissions = FileMode(binary.LittleEndian.Uint32(b[idx : idx+4]))
	cr.Mode = OpenMode(b[idx+4])
	return nil
}

// CreateResponse returns the qid of the file, as well as iounit, which is a
// read/write size that is guaranteed to be successfully written/read, or 0
// for no such guarantee.
type CreateResponse struct {
	Tag

	// Qid is the qid of the opened file.
	Qid Qid

	// IOUnit is the maximum amount of data that can be read/written by a single
	// call, or 0 for no specification.
	IOUnit uint32
}

func (cr *CreateResponse) EncodedSize() int { return 2 + 13 + 4 }

func (cr *CreateResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(cr.Tag))
	b[3] = byte(cr.Qid.Type)
	binary.LittleEndian.PutUint32(b[3:7], cr.Qid.Version)
	binary.LittleEndian.PutUint64(b[7:15], cr.Qid.Path)
	binary.LittleEndian.PutUint32(b[15:19], cr.IOUnit)
	return nil
}

func (cr *CreateResponse) Unmarshal(b []byte) error {
	if len(b) < 2+13+4 {
		return ErrPayloadTooShort
	}
	cr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	cr.Qid.Type = QidType(b[3])
	cr.Qid.Version = binary.LittleEndian.Uint32(b[3:7])
	cr.Qid.Path = binary.LittleEndian.Uint64(b[7:15])
	cr.IOUnit = binary.LittleEndian.Uint32(b[15:19])
	return nil
}

// ReadRequest is used to read data from an open file.
type ReadRequest struct {
	Tag

	// Fid is the fid of the file to read.
	Fid Fid

	// Offset is used to continue a previous read or to seek in the file.
	Offset uint64

	// Count is the maximum amount of byte requested.
	Count uint32
}

func (rr *ReadRequest) EncodedSize() int { return 2 + 4 + 8 + 4 }

func (rr *ReadRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(rr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(rr.Fid))
	binary.LittleEndian.PutUint64(b[6:14], rr.Offset)
	binary.LittleEndian.PutUint32(b[14:18], rr.Count)
	return nil
}

func (rr *ReadRequest) Unmarshal(b []byte) error {
	if len(b) < 2+4+8+4 {
		return ErrPayloadTooShort
	}

	rr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	rr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	rr.Offset = binary.LittleEndian.Uint64(b[6:14])
	rr.Count = binary.LittleEndian.Uint32(b[14:18])
	return nil
}

// ReadResponse  is used to return the read data.
type ReadResponse struct {
	Tag

	// Data is the data that was read.
	Data []byte
}

func (rr *ReadResponse) EncodedSize() int { return 2 + 4 + len(rr.Data) }

func (rr *ReadResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(rr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(len(rr.Data)))
	copy(b[6:], rr.Data)
	return nil
}

func (rr *ReadResponse) Unmarshal(b []byte) error {
	if len(b) < 2+4 {
		return ErrPayloadTooShort
	}

	rr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	l := int(binary.LittleEndian.Uint32(b[2:6]))
	if len(b) < 2+4+l {
		return ErrPayloadTooShort
	}
	rr.Data = make([]byte, l)
	copy(rr.Data, b[6:6+l])
	return nil
}

// WriteRequest is used to write to an open file.
type WriteRequest struct {
	Tag

	// Fid is the file to write to.
	Fid Fid

	// Offset is used to continue a previous write or to seek.
	Offset uint64

	// Data is the data to write.
	Data []byte
}

func (wr *WriteRequest) EncodedSize() int {
	return 2 + 4 + 8 + 4 + len(wr.Data)
}

func (wr *WriteRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(wr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(wr.Fid))
	binary.LittleEndian.PutUint64(b[6:14], wr.Offset)
	binary.LittleEndian.PutUint32(b[14:18], uint32(len(wr.Data)))
	copy(b[18:], wr.Data)
	return nil
}

func (wr *WriteRequest) Unmarshal(b []byte) error {
	t := 2 + 4 + 8 + 4
	if len(b) < t {
		return ErrPayloadTooShort
	}

	wr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	wr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	wr.Offset = binary.LittleEndian.Uint64(b[6:14])

	l := int(binary.LittleEndian.Uint32(b[14:18]))
	if len(b) < t+l {
		return ErrPayloadTooShort
	}

	wr.Data = make([]byte, l)
	copy(wr.Data, b[18:18+l])
	return nil
}

// WriteResponse is used to inform of how much data was written.
type WriteResponse struct {
	Tag

	// Count is the amount of written data.
	Count uint32
}

func (wr *WriteResponse) EncodedSize() int { return 2 + 4 }

func (wr *WriteResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(wr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], wr.Count)
	return nil
}

func (wr *WriteResponse) Unmarshal(b []byte) error {
	if len(b) < 2+4 {
		return ErrPayloadTooShort
	}

	wr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	wr.Count = binary.LittleEndian.Uint32(b[2:6])
	return nil
}

// ClunkRequest is used to clear a fid, allowing it to be reused.
type ClunkRequest struct {
	Tag

	// Fid is the fid to clunk.
	Fid Fid
}

func (cr *ClunkRequest) EncodedSize() int { return 2 + 4 }

func (cr *ClunkRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(cr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(cr.Fid))
	return nil
}

func (cr *ClunkRequest) Unmarshal(b []byte) error {
	if len(b) < 2+4 {
		return ErrPayloadTooShort
	}

	cr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	cr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	return nil
}

// ClunkResponse indicates a successful clunk.
type ClunkResponse struct {
	Tag
}

func (cr *ClunkResponse) EncodedSize() int { return 2 }

func (cr *ClunkResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(cr.Tag))
	return nil
}

func (cr *ClunkResponse) Unmarshal(b []byte) error {
	if len(b) < 2 {
		return ErrPayloadTooShort
	}

	cr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	return nil
}

// RemoveRequest is used to clunk a fid and remove the file if possible.
type RemoveRequest struct {
	Tag

	// Fid is the fid to clunk and potentially remove.
	Fid Fid
}

func (rr *RemoveRequest) EncodedSize() int { return 2 + 4 }

func (rr *RemoveRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(rr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(rr.Fid))
	return nil
}

func (rr *RemoveRequest) Unmarshal(b []byte) error {
	if len(b) < 2+4 {
		return ErrPayloadTooShort
	}

	rr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	rr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	return nil
}

// RemoveResponse indicates a successful clunk, but not necessarily a successful remove.
type RemoveResponse struct {
	Tag
}

func (rr *RemoveResponse) EncodedSize() int { return 2 }

func (rr *RemoveResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(rr.Tag))
	return nil
}

func (rr *RemoveResponse) Unmarshal(b []byte) error {
	if len(b) < 2 {
		return ErrPayloadTooShort
	}

	rr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	return nil
}

// StatRequest is used to retrieve the Stat struct of a file
type StatRequest struct {
	Tag

	// Fid is the fid to retrieve Stat for.
	Fid Fid
}

func (sr *StatRequest) EncodedSize() int { return 2 + 4 }

func (sr *StatRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(sr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(sr.Fid))
	return nil
}

func (sr *StatRequest) Unmarshal(b []byte) error {
	if len(b) < 2+4 {
		return ErrPayloadTooShort
	}

	sr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	sr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	return nil
}

// StatResponse contains the Stat struct of a file.
type StatResponse struct {
	Tag

	// Stat is the requested Stat struct.
	Stat Stat
}

func (sr *StatResponse) EncodedSize() int {
	return 2 + 2 + sr.Stat.EncodedSize()
}

func (sr *StatResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(sr.Tag))
	binary.LittleEndian.PutUint16(b[2:4], uint16(sr.Stat.EncodedSize()))
	return sr.Stat.Marshal(b[4:])
}

func (sr *StatResponse) Unmarshal(b []byte) error {
	if len(b) < 2+2 {
		return ErrPayloadTooShort
	}

	sr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	return sr.Stat.Unmarshal(b[4:])
}

// WriteStatRequest attempts to apply a Stat struct to a file. This requires a
// combination of write permissions to the file as well as to the parent
// directory, depending on the properties changed. Properties can be set to "no
// change" values, which for strings are empty strings, and for integral values
// are the maximum unsigned value of their respective types. The write is
// either completely successful with all changes applied, or failed with no
// changes applied. The server must not perform a partial application of the
// Stat structure.
type WriteStatRequest struct {
	Tag

	// Fid is the file to modify the Stat struct for.
	Fid Fid

	// Stat is the Stat struct to apply.
	Stat Stat
}

func (wsr *WriteStatRequest) EncodedSize() int {
	return 2 + 4 + 2 + wsr.Stat.EncodedSize()
}

func (wsr *WriteStatRequest) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(wsr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(wsr.Fid))
	binary.LittleEndian.PutUint16(b[6:8], uint16(wsr.Stat.EncodedSize()))
	return wsr.Stat.Marshal(b[8:])
}

func (wsr *WriteStatRequest) Unmarshal(b []byte) error {
	if len(b) < 2+4+2 {
		return ErrPayloadTooShort
	}

	wsr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	wsr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	return wsr.Stat.Unmarshal(b[8:])
}

// WriteStatResponse indicates a successful application of a Stat structure.
type WriteStatResponse struct {
	Tag
}

func (wsr *WriteStatResponse) EncodedSize() int { return 2 }

func (wsr *WriteStatResponse) Marshal(b []byte) error {
	binary.LittleEndian.PutUint16(b[0:2], uint16(wsr.Tag))
	return nil
}

func (wsr *WriteStatResponse) Unmarshal(b []byte) error {
	if len(b) < 2 {
		return ErrPayloadTooShort
	}
	wsr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	return nil
}
