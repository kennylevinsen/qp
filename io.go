package qp

import (
	"encoding/binary"
	"io"
)

// Read reads until the provided slice is full or an io error occurs.
func read(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)
	return err
}

// Write write all the provided data unless and io error occurs.
func write(w io.Writer, b []byte) error {
	var (
		written int
		err     error
		l       = len(b)
	)
	for written < l {
		written, err = w.Write(b[written:])
		if err != nil {
			return err
		}
	}

	return nil
}

// readByte reads a single byte.
func readByte(r io.Reader) (byte, error) {
	b := make([]byte, 1)
	err := read(r, b)
	if err != nil {
		return 0, err
	}

	return b[0], nil
}

// writeByte writes a single byte.
func writeByte(w io.Writer, b byte) error {
	return write(w, []byte{b})
}

// readUint16 reads a uint16.
func readUint16(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	err := read(r, b)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint16(b), nil
}

// writeUint16 writes a uint16.
func writeUint16(w io.Writer, i uint16) error {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return write(w, b)
}

// readUint32 reads a uint32.
func readUint32(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	err := read(r, b)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(b), nil
}

// writeUint32 writes a uint32.
func writeUint32(w io.Writer, i uint32) error {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return write(w, b)
}

// readUint64 read a uint64.
func readUint64(r io.Reader) (uint64, error) {
	b := make([]byte, 8)
	err := read(r, b)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(b), nil
}

// writeUint64 writes a uint64.
func writeUint64(w io.Writer, i uint64) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, i)
	return write(w, b)
}

// readTag reads a tag.
func readTag(r io.Reader) (Tag, error) {
	t, err := readUint16(r)
	return Tag(t), err
}

// writeTag writes a tag.
func writeTag(w io.Writer, t Tag) error {
	return writeUint16(w, uint16(t))
}

// readFid reads a fid.
func readFid(r io.Reader) (Fid, error) {
	f, err := readUint32(r)
	return Fid(f), err
}

// writeFid writes a fid.
func writeFid(w io.Writer, f Fid) error {
	return writeUint32(w, uint32(f))
}

// readString reads a string.
func readString(r io.Reader) (string, error) {
	l, err := readUint16(r)
	if err != nil {
		return "", err
	}

	b := make([]byte, int(l))
	err = read(r, b)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// writeString writes a string.
func writeString(w io.Writer, s string) error {
	err := writeUint16(w, uint16(len(s)))
	if err != nil {
		return err
	}

	err = write(w, []byte(s))
	if err != nil {
		return err
	}
	return nil
}

// readOpenMode reads openmode.
func readOpenMode(r io.Reader) (OpenMode, error) {
	o, err := readByte(r)
	return OpenMode(o), err
}

// writeOpenMode writes openmode.
func writeOpenMode(w io.Writer, o OpenMode) error {
	return writeByte(w, byte(o))
}

// readQidType reads qid type.
func readQidType(r io.Reader) (QidType, error) {
	o, err := readByte(r)
	return QidType(o), err
}

// writeQidType writes qid type.
func writeQidType(w io.Writer, o QidType) error {
	return writeByte(w, byte(o))
}

// readMessageType reads message type.
func readMessageType(r io.Reader) (MessageType, error) {
	mt, err := readByte(r)
	return MessageType(mt), err
}

// writeMessageType writes message type.
func writeMessageType(w io.Writer, mt MessageType) error {
	return writeByte(w, byte(mt))
}

// readFileMode reads filemode.
func readFileMode(r io.Reader) (FileMode, error) {
	fm, err := readUint32(r)
	return FileMode(fm), err
}

// writeFileMode writes filemode.
func writeFileMode(w io.Writer, fm FileMode) error {
	return writeUint32(w, uint32(fm))
}
