package qp

import "io"

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

// Decode decodes a stream into the message.
func (sr *SessionRequestDote) Decode(r io.Reader) error {
	var err error
	if sr.Tag, err = readTag(r); err != nil {
		return err
	}
	if err = read(r, sr.Key[:]); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (sr *SessionRequestDote) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, sr.Tag); err != nil {
		return err
	}
	if err = write(w, sr.Key[:]); err != nil {
		return err
	}
	return nil
}

// SessionResponseDote is used to indicate a successful session restore.
type SessionResponseDote struct {
	Tag
}

// EncodedLength returns the length the message will be when serialized.
func (sr *SessionResponseDote) EncodedLength() int {
	return 2
}

// Decode decodes a stream into the message.
func (sr *SessionResponseDote) Decode(r io.Reader) error {
	var err error
	if sr.Tag, err = readTag(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (sr *SessionResponseDote) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, sr.Tag); err != nil {
		return err
	}
	return nil
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

// Decode decodes a stream into the message.
func (srr *SimpleReadRequestDote) Decode(r io.Reader) error {
	var err error
	if srr.Tag, err = readTag(r); err != nil {
		return err
	}
	if srr.Fid, err = readFid(r); err != nil {
		return err
	}
	var arr uint16
	if arr, err = readUint16(r); err != nil {
		return err
	}
	srr.Names = make([]string, arr)
	for i := 0; i < int(arr); i++ {
		if srr.Names[i], err = readString(r); err != nil {
			return err
		}
	}
	return nil
}

// Encode encodes the message into a stream.
func (srr *SimpleReadRequestDote) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, srr.Tag); err != nil {
		return err
	}
	if err = writeFid(w, srr.Fid); err != nil {
		return err
	}
	if err = writeUint16(w, uint16(len(srr.Names))); err != nil {
		return err
	}
	for i := range srr.Names {
		if err = writeString(w, srr.Names[i]); err != nil {
			return err
		}
	}
	return nil
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

// Decode decodes a stream into the message.
func (srr *SimpleReadResponseDote) Decode(r io.Reader) error {
	var err error
	if srr.Tag, err = readTag(r); err != nil {
		return err
	}
	var l uint32
	if l, err = readUint32(r); err != nil {
		return err
	}
	srr.Data = make([]byte, l)
	if err = read(r, srr.Data); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (srr *SimpleReadResponseDote) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, srr.Tag); err != nil {
		return err
	}
	if err = writeUint32(w, uint32(len(srr.Data))); err != nil {
		return err
	}
	if err = write(w, srr.Data); err != nil {
		return err
	}
	return nil
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

// Decode decodes a stream into the message.
func (swr *SimpleWriteRequestDote) Decode(r io.Reader) error {
	var err error
	if swr.Tag, err = readTag(r); err != nil {
		return err
	}
	if swr.Fid, err = readFid(r); err != nil {
		return err
	}
	var arr uint16
	if arr, err = readUint16(r); err != nil {
		return err
	}
	swr.Names = make([]string, arr)
	for i := 0; i < int(arr); i++ {
		if swr.Names[i], err = readString(r); err != nil {
			return err
		}
	}
	var l uint32
	if l, err = readUint32(r); err != nil {
		return err
	}
	swr.Data = make([]byte, l)
	if err = read(r, swr.Data); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (swr *SimpleWriteRequestDote) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, swr.Tag); err != nil {
		return err
	}
	if err = writeFid(w, swr.Fid); err != nil {
		return err
	}
	if err = writeUint16(w, uint16(len(swr.Names))); err != nil {
		return err
	}
	for i := range swr.Names {
		if err = writeString(w, swr.Names[i]); err != nil {
			return err
		}
	}
	if err = writeUint32(w, uint32(len(swr.Data))); err != nil {
		return err
	}
	if err = write(w, swr.Data); err != nil {
		return err
	}
	return nil
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

// Decode decodes a stream into the message.
func (swr *SimpleWriteResponseDote) Decode(r io.Reader) error {
	var err error
	if swr.Tag, err = readTag(r); err != nil {
		return err
	}
	if swr.Count, err = readUint32(r); err != nil {
		return err
	}
	return nil
}

// Encode encodes the message into a stream.
func (swr *SimpleWriteResponseDote) Encode(w io.Writer) error {
	var err error
	if err = writeTag(w, swr.Tag); err != nil {
		return err
	}
	if err = writeUint32(w, swr.Count); err != nil {
		return err
	}
	return nil
}
