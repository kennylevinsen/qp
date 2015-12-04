package qp

import "encoding/binary"

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

func (sr *SessionRequestDote) UnmarshalBinary(b []byte) error {
	if len(b) < 2+8 {
		return ErrPayloadTooShort
	}
	sr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	copy(sr.Key[:], b[2:10])
	return nil
}

func (sr *SessionRequestDote) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+8)
	binary.LittleEndian.PutUint16(b[0:2], uint16(sr.Tag))
	copy(b[2:], sr.Key[:])
	return b, nil
}

// SessionResponseDote is used to indicate a successful session restore.
type SessionResponseDote struct {
	Tag
}

func (sr *SessionResponseDote) UnmarshalBinary(b []byte) error {
	if len(b) < 2 {
		return ErrPayloadTooShort
	}
	sr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	return nil
}

func (sr *SessionResponseDote) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b[0:2], uint16(sr.Tag))
	return b, nil
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

func (srr *SimpleReadRequestDote) UnmarshalBinary(b []byte) error {
	t := 2 + 4 + 2
	if len(b) < t {
		return ErrPayloadTooShort
	}
	srr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	srr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	l := int(binary.LittleEndian.Uint16(b[6:8]))
	idx := 8
	srr.Names = make([]string, l)
	for i := range srr.Names {
		if len(b) < t+2 {
			return ErrPayloadTooShort
		}
		l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
		if len(b) < t+2+l {
			return ErrPayloadTooShort
		}
		srr.Names[i] = string(b[idx+2 : idx+2+l])
		idx += 2 + l
		t += 2 + l
	}
	return nil
}

func (srr *SimpleReadRequestDote) MarshalBinary() ([]byte, error) {
	l := 2 + 4 + 2
	for i := range srr.Names {
		l += 2 + len(srr.Names[i])
	}
	b := make([]byte, l)
	binary.LittleEndian.PutUint16(b[0:2], uint16(srr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(srr.Fid))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(srr.Names)))
	idx := 8
	for i := range srr.Names {
		l := len(srr.Names[i])
		binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(l))
		copy(b[idx+2:], []byte(srr.Names[i]))
		idx += 2 + l
	}
	return b, nil
}

// SimpleReadResponseDote is used to return the read data.
type SimpleReadResponseDote struct {
	Tag

	Data []byte
}

func (srr *SimpleReadResponseDote) UnmarshalBinary(b []byte) error {
	if len(b) < 2+4 {
		return ErrPayloadTooShort
	}

	srr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	l := int(binary.LittleEndian.Uint32(b[2:6]))
	if len(b) < 2+4+l {
		return ErrPayloadTooShort
	}
	srr.Data = make([]byte, l)
	copy(srr.Data, b[6:6+l])
	return nil
}

func (srr *SimpleReadResponseDote) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+4+len(srr.Data))
	binary.LittleEndian.PutUint16(b[0:2], uint16(srr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(len(srr.Data)))
	copy(b[6:], srr.Data)
	return b, nil
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

func (swr *SimpleWriteRequestDote) UnmarshalBinary(b []byte) error {
	t := 2 + 4 + 2 + 4
	if len(b) < t {
		return ErrPayloadTooShort
	}
	swr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	swr.Fid = Fid(binary.LittleEndian.Uint32(b[2:6]))
	l := int(binary.LittleEndian.Uint16(b[6:8]))
	idx := 8
	swr.Names = make([]string, l)
	for i := range swr.Names {
		if len(b) < t+2 {
			return ErrPayloadTooShort
		}
		l = int(binary.LittleEndian.Uint16(b[idx : idx+2]))
		if len(b) < t+2+l {
			return ErrPayloadTooShort
		}
		swr.Names[i] = string(b[idx+2 : idx+2+l])
		idx += 2 + l
		t += 2 + l
	}
	l = int(binary.LittleEndian.Uint32(b[idx : idx+4]))
	if len(b) < t+l {
		return ErrPayloadTooShort
	}
	swr.Data = make([]byte, l)
	copy(swr.Data, b[idx+4:idx+4+l])
	return nil
}

func (swr *SimpleWriteRequestDote) MarshalBinary() ([]byte, error) {
	l := 2 + 4 + 2 + 4 + len(swr.Data)
	for i := range swr.Names {
		l += 2 + len(swr.Names[i])
	}
	b := make([]byte, l)
	binary.LittleEndian.PutUint16(b[0:2], uint16(swr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], uint32(swr.Fid))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(swr.Names)))
	idx := 8
	for i := range swr.Names {
		l := len(swr.Names[i])
		binary.LittleEndian.PutUint16(b[idx:idx+2], uint16(l))
		copy(b[idx+2:], []byte(swr.Names[i]))
		idx += 2 + l
	}
	binary.LittleEndian.PutUint32(b[idx:idx+4], uint32(len(swr.Data)))
	copy(b[idx+4:], swr.Data)
	return b, nil
}

// SimpleWriteResponseDote is used to inform of how much data was written.
type SimpleWriteResponseDote struct {
	Tag

	Count uint32
}

func (swr *SimpleWriteResponseDote) UnmarshalBinary(b []byte) error {
	if len(b) < 2+4 {
		return ErrPayloadTooShort
	}

	swr.Tag = Tag(binary.LittleEndian.Uint16(b[0:2]))
	swr.Count = binary.LittleEndian.Uint32(b[2:6])
	return nil
}

func (swr *SimpleWriteResponseDote) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2+4)
	binary.LittleEndian.PutUint16(b[0:2], uint16(swr.Tag))
	binary.LittleEndian.PutUint32(b[2:6], swr.Count)
	return b, nil
}

// EncodedLength returns the length the message will be when serialized.
func (swr *SimpleWriteResponseDote) EncodedLength() int {
	return 2 + 4
}
