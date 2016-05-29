package qp

import (
	"encoding"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

var (
	// ErrPayloadTooShort indicates that the message was not complete.
	ErrPayloadTooShort = errors.New("payload too short")

	// ErrMessageTooBig indicates that the message, when encoded and wrapped in
	// container, does not fit in the configured message size.
	ErrMessageTooBig = errors.New("message size larger than buffer")
)

// Protocol defines a protocol message encoder/decoder
type Protocol interface {
	MessageType(Message) (MessageType, error)
	Message(MessageType) (Message, error)
}

// Default is the protocol used by the raw Encode and Decode functions.
var Default = NineP2000

// MessageType is the type of the contained message.
type MessageType byte

// Message is an interface describing an item that can encode itself to a
// writer, decode itself from a reader. It is also capable of getting the
// message tag, which is merely a convenience feature to save a type assert
// for access to the tag.
type Message interface {
	encoding.BinaryUnmarshaler
	encoding.BinaryMarshaler
	GetTag() Tag
}

// Encoder handles writes encoded messages to an io.Writer. Encoder is thread
// safe, and may be called in parallel from arbitrary goroutines.
type Encoder struct {
	// Protocol is the protocol codec used for encoding messages.
	Protocol Protocol

	// Writer is the writer to encode messages to.
	Writer io.Writer

	// MessageSize is the maximum message size negotiated for the protocol. It
	// is used to enforce a limit on writes.
	MessageSize uint32

	// writeLock is used to synchronize writes. Without it, messages would end
	// up interleaved and incomprehensible.
	writeLock sync.Mutex
}

// WriteMessage encodes a message and writes it to the Encoders associated
// io.Writer.
func (e *Encoder) WriteMessage(m Message) error {
	var (
		mt             MessageType
		msgbuf, header []byte
		err            error
	)

	if mt, err = e.Protocol.MessageType(m); err != nil {
		return err
	}

	if msgbuf, err = m.MarshalBinary(); err != nil {
		return err
	}

	if len(msgbuf)+HeaderSize > int(e.MessageSize) {
		return ErrMessageTooBig
	}

	header = make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(msgbuf)+HeaderSize))
	header[4] = byte(mt)

	e.writeLock.Lock()
	defer e.writeLock.Unlock()

	if _, err = e.Writer.Write(header); err != nil {
		return err
	}

	if _, err = e.Writer.Write(msgbuf); err != nil {
		return err
	}

	return nil
}

// Decoder reads messages from an io.Reader. It exposes buffered reading through
// ReadMessage. A Decoder is not thread safe. Only one goroutine may call
// ReadMessage at a time.
type Decoder struct {
	// Protocol is the protocol codec used for decoding messages.
	Protocol Protocol

	// Reader is the reader to decode from.
	Reader io.Reader

	// Greedy enables greedy decoding, which is whether or not the decoder
	// should try to read more than just the next message into the buffer.
	// This can save significant amount of Read calls, but must not be set if
	// the user intents to change the reader soon, as it may result in losing
	// a partial read. A common thing to do would be to enable Greedy after
	// protocol negotiation.
	Greedy bool

	// MessageSize is the maximum message size negotiated for the protocol. It
	// is used to allocate the decoding buffer.
	MessageSize uint32

	// total is the count of bytes in the buffer. It is used to keep track
	// of buffer usage (read offset and cleanup), and is not used by the
	// actual decoding loop.
	total uint32

	// needed is the amount of bytes missing. It should only be
	// incremented or decremented, never assigned. This ensures that more
	// than one message can be read into the buffer before the decoder is
	// ready to read them. If needed is zero, it means that all the
	// requested data have been read. If it is negative, then more data
	// then the request has been read. The decoding loop continues until
	// needed is > 0.
	needed int

	// size is the decoded message body size, not including message
	// header. It is stored in order to increment the ptr correctly after
	// reading a message.
	size uint32

	// ptr is the start index at the buffer at the current time. It is
	// incremented as we read through the buffer, and reset when we clean
	// the buffer.
	ptr uint32

	// m is the current decoded message. It is nil when we have not yet
	// decoded a header, and set to an zero-initialized message struct
	// when we have received the header. Comparing it to nil is used to
	// check what state the decoder is in (header decoding vs. body
	// decoding).
	m Message

	// buffer is the reading buffer.
	buffer []byte
}

// Reset resets the decoding state machine and reallocates the buffer to the
// current MessageSize. Reset will return an error if the buffer isn't empty,
// which may be the case if Greedy decoding has already been used.
func (d *Decoder) Reset() error {
	if d.total-d.ptr != 0 {
		return errors.New("buffer is not empty")
	}
	d.total = 0
	d.size = 0
	d.ptr = 0
	d.m = nil
	d.buffer = make([]byte, d.MessageSize)
	d.needed = HeaderSize
	return nil
}

// simpleRead is an inefficient but safe and stateless decoding mechanism.
func (d *Decoder) simpleRead() (Message, error) {
	b := make([]byte, 5)
	_, err := io.ReadFull(d.Reader, b)
	if err != nil {
		return nil, err
	}

	s := binary.LittleEndian.Uint32(b[0:4]) - HeaderSize
	mt := MessageType(b[4])
	m, err := d.Protocol.Message(mt)
	if err != nil {
		return nil, err
	}

	b = make([]byte, s)
	_, err = io.ReadFull(d.Reader, b)
	if err != nil {
		return nil, err
	}

	err = m.UnmarshalBinary(b)
	return m, err
}

// greedyRead is complicated and unsafe (parameters cannot be changed). The
// upside is that it can save a considerable amount of syscalls.
func (d *Decoder) greedyRead() (Message, error) {
	if d.buffer == nil {
		// Let's initialize.
		d.Reset()
	}

	var (
		err, readerr    error
		n, limit, total int
	)
	for {
		// Handle the data we got.
		for d.needed <= 0 {
			if d.m == nil { // Read a header if no message has been prepared.
				s := binary.LittleEndian.Uint32(d.buffer[d.ptr : d.ptr+4])
				if s > uint32(len(d.buffer)) {
					return nil, ErrMessageTooBig
				}

				d.size = s - HeaderSize
				mt := MessageType(d.buffer[d.ptr+4])

				// Update message body size, missing bytes and the current ptr.
				d.needed += int(d.size)
				d.ptr += HeaderSize

				// We try to fetch the message struct immediately - better to fail
				// early rather than late.
				if d.m, err = d.Protocol.Message(mt); err != nil {
					return nil, err
				}

			} else { // Otherwise, read a body for the message.
				if err = d.m.UnmarshalBinary(d.buffer[d.ptr : d.ptr+d.size]); err != nil {
					return nil, err
				}

				d.needed += HeaderSize
				d.ptr += d.size
				d.size = 0

				m := d.m
				d.m = nil
				return m, nil
			}
		}

		// Let's see if any readerr was present from last iteration...
		if readerr != nil {
			return nil, readerr
		}

		// Buffer cleanup.
		limit = len(d.buffer)
		total = int(d.total)
		if d.needed > limit-total {
			// The remaining part of the buffer is smaller than what we need,
			// so time for a cleaning. We could do it unconditionally for
			// every message, but a lot of small messages can usually fit in
			// the buffer, so why bother?
			copy(d.buffer, d.buffer[d.ptr:d.total])
			d.total -= d.ptr
			total = int(d.total)
			d.ptr = 0
		}

		// We need more data!
		n, readerr = d.Reader.Read(d.buffer[d.total:limit])
		d.total += uint32(n)
		d.needed -= n
	}
}

// ReadMessage executes the decoder loop, returning the next message. It will
// continue reading from the configured reader until a message is found or an
// error occurs. NextMessage calls Reset if the internal buffer is nil for
// initialization.
func (d *Decoder) ReadMessage() (Message, error) {
	if d.Greedy {
		return d.greedyRead()
	}
	return d.simpleRead()
}
