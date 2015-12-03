package qp

import (
	"encoding"
	"errors"
	"io"
)

// Default is the protocol used by the raw Encode and Decode functions.
var Default = NineP2000

// Protocol defines a protocol message encoder/decoder
type Protocol interface {
	Decode(r io.Reader) (Message, error)
	Encode(w io.Writer, m Message) error
}

// MessageType is the type of the contained message.
type MessageType byte

// Message is an interface describing an item that can encode itself to a
// writer, decode itself from a reader, and inform how large the encoded form
// would be at the current time. It is also capable of getting/setting the
// message tag, which is merely a convenience feature to save a type assert
// for access to the tag.
type Message interface {
	encoding.BinaryUnmarshaler
	encoding.BinaryMarshaler
	EncodedLength() int
	GetTag() Tag
}

// DecodeHdr reads 5 bytes and returns the decoded size and message type. It
// may return an error if reading from the Reader fails.
func DecodeHdr(r io.Reader) (uint32, MessageType, error) {
	var (
		size uint32
		mt   MessageType
		err  error
	)

	if size, err = readUint32(r); err != nil {
		return 0, 0, err
	}

	if mt, err = readMessageType(r); err != nil {
		return size, 0, err
	}

	return size, mt, nil
}

// Codec encodes/decodes messages using the provided message type <-> message
// conversion.
type Codec struct {
	M2MT func(Message) (MessageType, error)
	MT2M func(MessageType) (Message, error)
}

// Decode decodes an entire message, including header, and returns the message.
// It may return an error if reading from the Reader fails, or if a message
// tries to consume more data than the size of the header indicated, making the
// message invalid.
func (c *Codec) Decode(r io.Reader) (Message, error) {
	var (
		size uint32
		mt   MessageType
		err  error
	)
	if size, mt, err = DecodeHdr(r); err != nil {
		return nil, err
	}

	size -= HeaderSize

	b := make([]byte, size)
	n, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	if n != int(size) {
		return nil, errors.New("short read")
	}

	m, err := c.MT2M(mt)
	if err != nil {
		return nil, err
	}

	if err = m.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return m, nil
}

// Encode write a header and message to the provided writer. It returns an
// error if writing failed.
func (c *Codec) Encode(w io.Writer, m Message) error {
	var err error
	var mt MessageType
	if mt, err = c.M2MT(m); err != nil {
		return err
	}

	var b []byte
	if b, err = m.MarshalBinary(); err != nil {
		return err
	}

	size := uint32(len(b) + HeaderSize)
	if err = writeUint32(w, size); err != nil {
		return err
	}

	if err = writeMessageType(w, mt); err != nil {
		return err
	}

	if err = write(w, b); err != nil {
		return err
	}

	return nil
}

// Decode is a convenience function for calling decode on the default
// protocol.
func Decode(r io.Reader) (Message, error) {
	return Default.Decode(r)
}

// Encode is a convenience function for calling encode on the default
// protocol.
func Encode(w io.Writer, d Message) error {
	return Default.Encode(w, d)
}
