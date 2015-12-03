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
var NineP2000 Protocol = &Codec{
	M2MT: MessageToMessageType,
	MT2M: MessageTypeToMessage,
}

// Tag is a unique identifier for a request. It is echoed by the response. It
// is the responsibility of the client to ensure that it is unique among all
// current requests.
type Tag uint16

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

func (q *Qid) UnmarshalBinary(b []byte) error {
	var err error
	idx := 0
	if q.Type, idx, err = nreadQidType(b, idx); err != nil {
		return err
	}
	if q.Version, idx, err = nreadUint32(b, idx); err != nil {
		return err
	}
	if q.Path, idx, err = nreadUint64(b, idx); err != nil {
		return err
	}
	return nil
}

func (q *Qid) MarshalBinary() ([]byte, error) {
	var b []byte
	b = nwriteQidType(b, q.Type)
	b = nwriteUint32(b, q.Version)
	b = nwriteUint64(b, q.Path)
	return b, nil
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

func (s *Stat) UnmarshalBinary(b []byte) error {
	var err error
	idx := 0
	if _, idx, err = nreadUint16(b, idx); err != nil {
		return err
	}
	if s.Type, idx, err = nreadUint16(b, idx); err != nil {
		return err
	}
	if s.Dev, idx, err = nreadUint32(b, idx); err != nil {
		return err
	}
	if err = s.Qid.UnmarshalBinary(b[idx : idx+13]); err != nil {
		return err
	}
	idx += 13
	if s.Mode, idx, err = nreadFileMode(b, idx); err != nil {
		return err
	}
	if s.Atime, idx, err = nreadUint32(b, idx); err != nil {
		return err
	}
	if s.Mtime, idx, err = nreadUint32(b, idx); err != nil {
		return err
	}
	if s.Length, idx, err = nreadUint64(b, idx); err != nil {
		return err
	}
	if s.Name, idx, err = nreadString(b, idx); err != nil {
		return err
	}
	if s.UID, idx, err = nreadString(b, idx); err != nil {
		return err
	}
	if s.GID, idx, err = nreadString(b, idx); err != nil {
		return err
	}
	if s.MUID, idx, err = nreadString(b, idx); err != nil {
		return err
	}
	return nil
}

func (s *Stat) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2)
	b = nwriteUint16(b, s.Type)
	b = nwriteUint32(b, s.Dev)
	x, err := s.Qid.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b = append(b, x...)
	b = nwriteFileMode(b, s.Mode)
	b = nwriteUint32(b, s.Atime)
	b = nwriteUint32(b, s.Mtime)
	b = nwriteUint64(b, s.Length)
	b = nwriteString(b, s.Name)
	b = nwriteString(b, s.UID)
	b = nwriteString(b, s.GID)
	b = nwriteString(b, s.MUID)
	binary.LittleEndian.PutUint16(b[0:2], uint16(len(b)-2))
	return b, nil
}

//
// Message type structs and the encode/decode methods below.
//

// VersionRequest is used to inform the server of the maximum size it intends
// to send or it can receive, as well as the maximum protocol version
// supported. The tag used for this request must be NOTAG.
type VersionRequest struct {
	Tag

	// MaxSize is the suggested absolute maximum message size for the
	// connection. The final negotiated value must be honoured. This field is
	// called "msize" in the official implementation.
	MaxSize uint32

	// Version is the suggested maximum protocol version for the connection.
	Version string
}

// VersionResponse is used to inform the client of maximum size and version,
// taking the clients VersionRequest into consideration. MaxSize in the reply
// must not be larger than MaxSize in the request, and the version must
// likewise be equal to or lower than the one in the requst.
type VersionResponse struct {
	Tag

	// MaxSize is the negotiated maximum message size for the connection. This
	// value must be honoured. This field is called "msize" in the official
	// implementation.
	MaxSize uint32

	// Version is the negotiated protocol version, or "unknown" if negotiation
	// failed.
	Version string
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

// AuthResponse is used to acknowledge the authentication protocol connection,
// and to return the matching Qid.
type AuthResponse struct {
	Tag

	// AuthQid is the Qid representing the special authentication file. This
	// field is called "aqid" in the official implementation.
	AuthQid Qid `len:"13"`
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

// AttachResponse acknowledges an attach.
type AttachResponse struct {
	Tag

	// Qid is the qid of the root node.
	Qid Qid `len:"13"`
}

// ErrorResponse is used when the server wants to report and error with the
// request. There is no ErrorRequest, as such a thing would not make sense.
type ErrorResponse struct {
	Tag

	// Error is the error string. This field is called "ename" in the official
	// implementation.
	Error string
}

// FlushRequest is used to cancel a pending request. The flushed tag can be
// used after a response have been received.
type FlushRequest struct {
	Tag

	// OldTag is the tag of the request to cancel.
	OldTag Tag
}

// FlushResponse is used to indicate a successful flush. Do note that
// FlushResponse have a peculiar behaviour when multiple flushes are pending.
type FlushResponse struct {
	Tag
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

// WalkResponse returns the qids for each successfully walked element. If the
// walk is successful, the amount of qids will be identical to the amount of
// names.
type WalkResponse struct {
	Tag

	// Qids are the qids for the successfully walked files.
	Qids []Qid
}

// OpenRequest is used to open a fid for reading/writing/executing.
type OpenRequest struct {
	Tag

	// Fid is the file to open.
	Fid Fid

	// Mode is the mode to open file under.
	Mode OpenMode
}

// OpenResponse returns the qid of the file, as well as iounit, which is a
// read/write size that is guaranteed to be sucessfully written/read, or 0 for
// no such guarantee.
type OpenResponse struct {
	Tag

	// Qid is the qid of the opened file.
	Qid Qid `len:"13"`

	// IOUnit is the maximum amount of data that can be read/written by a single
	// call, or 0 for no specification.
	IOUnit uint32
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

// CreateResponse returns the qid of the file, as well as iounit, which is a
// read/write size that is guaranteed to be sucessfully written/read, or 0 for
// no such guarantee.
type CreateResponse struct {
	Tag

	// Qid is the qid of the opened file.
	Qid Qid `len:"13"`

	// IOUnit is the maximum amount of data that can be read/written by a single
	// call, or 0 for no specification.
	IOUnit uint32
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

// ReadResponse  is used to return the read data.
type ReadResponse struct {
	Tag

	// Data is the data that was read.
	Data []byte
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

// WriteResponse is used to inform of how much data was written.
type WriteResponse struct {
	Tag

	// Count is the amount of written data.
	Count uint32
}

// ClunkRequest is used to clear a fid, allowing it to be reused.
type ClunkRequest struct {
	Tag

	// Fid is the fid to clunk.
	Fid Fid
}

// ClunkResponse indicates a successful clunk.
type ClunkResponse struct {
	Tag
}

// RemoveRequest is used to clunk a fid and remove the file if possible.
type RemoveRequest struct {
	Tag

	// Fid is the fid to clunk and potentially remove.
	Fid Fid
}

// RemoveResponse indicates a successful clunk, but not necessarily a successful remove.
type RemoveResponse struct {
	Tag
}

// StatRequest is used to retrieve the Stat struct of a file
type StatRequest struct {
	Tag

	// Fid is the fid to retrieve Stat for.
	Fid Fid
}

// StatResponse contains the Stat struct of a file.
type StatResponse struct {
	Tag

	// Stat is the requested Stat struct.
	Stat Stat `len:"uint16"`
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
	Stat Stat `len:"uint16"`
}

// WriteStatResponse indicates a successful application of a Stat structure.
type WriteStatResponse struct {
	Tag
}
