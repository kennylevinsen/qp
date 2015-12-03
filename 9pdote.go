package qp

// NineP2000Dote implements 9P2000.e encoding and decoding. 9P2000.e is meant
// to provide the ability to restore a session, as well as shorthands for
// combined walk + open + read/write + clunk operations, which can be a lot of
// roundtrips for many small files.
//
// Message types
//
// 9P2000.e adds the following messages:
//    SessionRequestDote:      size[4] Tsession tag[2] key[8]
//    SessionResponseDote:     size[4] Rsession tag[2]
//    SimpleReadRequestDote:   size[4] Tsread tag[2] fid[4] nwname[2] nwname*(wname[s])
//    SimpleReadResponseDote:  size[4] Rsread tag[2] count[4] data[count]
//    SimpleWriteRequestDote:  size[4] Tswrite tag[2] fid[4] nwname[2] nwname*(wname[s]) count[4] data[count]
//    SimpleWriteResponseDote: size[4] Rswrite tag[2] count[4]
var NineP2000Dote Protocol = &Codec{
	M2MT: MessageToMessageTypeDote,
	MT2M: MessageTypeToMessageDote,
}

// SessionRequestDote is used to restore a previous session. The key
// representing the session must have been obtained in the previous session
// through other means, such as an authentication scheme. The request must be
// the first request after a Version request, and must have the tag set to
// NOTAG. If the restore fails, the client may continue with the connection as
// a new session.
type SessionRequestDote struct {
	Tag

	Key [8]byte
}

// EncodedLength returns the length the message will be when serialized.
func (sr *SessionRequestDote) EncodedLength() int {
	return 2 + 8
}

// SessionResponseDote is used to indicate a successful session restore.
type SessionResponseDote struct {
	Tag
}

// EncodedLength returns the length the message will be when serialized.
func (sr *SessionResponseDote) EncodedLength() int {
	return 2
}

// SimpleReadRequestDote is used to quickly read a file. The request is
// equivalent to walking from the provided fid to the provided names, opening
// the new fid, reading as much as possible from the file and clunking the
// fid. While redundant, the request significantly reduces the required amount
// of roundtrips for many small reads.
type SimpleReadRequestDote struct {
	Tag

	Fid Fid

	Names []string
}

// EncodedLength returns the length the message will be when serialized.
func (srr *SimpleReadRequestDote) EncodedLength() int {
	x := 0
	for i := range srr.Names {
		x += 2 + len(srr.Names[i])
	}
	return 2 + 4 + 2 + x
}

// SimpleReadResponseDote is used to return the read data.
type SimpleReadResponseDote struct {
	Tag

	Data []byte
}

// EncodedLength returns the length the message will be when serialized.
func (srr *SimpleReadResponseDote) EncodedLength() int {
	return 2 + 4 + len(srr.Data)
}

// SimpleWriteRequestDote is used to quickly create a file if it doesn't
// exist, truncate and write to the file. The request is equivalent to walking
// from the provided fid to the second last provided name, creating the last
// name while disregarding failure in the new fid, walking to the last name,
// opening the new fid for truncated write, writing as much as possible to the
// file and clunking the fid. While redundant, the request significantly
// reduces the required amount of roundtrips for many small writes.
type SimpleWriteRequestDote struct {
	Tag

	Fid Fid

	Names []string

	Data []byte
}

// EncodedLength returns the length the message will be when serialized.
func (swr *SimpleWriteRequestDote) EncodedLength() int {
	x := 0
	for i := range swr.Names {
		x += 2 + len(swr.Names[i])
	}
	return 2 + 4 + 2 + x + 4 + len(swr.Data)
}

// SimpleWriteResponseDote is used to inform of how much data was written.
type SimpleWriteResponseDote struct {
	Tag

	Count uint32
}

// EncodedLength returns the length the message will be when serialized.
func (swr *SimpleWriteResponseDote) EncodedLength() int {
	return 2 + 4
}
