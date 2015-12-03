package qp

import (
	"encoding"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
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

func decodeQid(b []byte, idx int) (Qid, int, error) {
	var err error
	q := Qid{}
	if q.Type, idx, err = nreadQidType(b, idx); err != nil {
		return q, idx, err
	}
	if q.Version, idx, err = nreadUint32(b, idx); err != nil {
		return q, idx, err
	}
	if q.Path, idx, err = nreadUint64(b, idx); err != nil {
		return q, idx, err
	}
	return q, idx, nil
}

func decode(b []byte, m interface{}) error {
	var err error
	v := reflect.ValueOf(m)
	k := v.Kind()
	switch k {
	case reflect.Interface, reflect.Ptr:
		v = v.Elem()
	}
	t := v.Type()
	n := v.NumField()
	idx := 0
	for i := 0; i < n; i++ {
		f := v.Field(i)
		switch f.Interface().(type) {
		case uint8:
			var x uint8
			x, idx, err = nreadByte(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case OpenMode:
			var x OpenMode
			x, idx, err = nreadOpenMode(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case uint16:
			var x uint16
			x, idx, err = nreadUint16(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case Tag:
			var x Tag
			x, idx, err = nreadTag(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case uint32:
			var x uint32
			x, idx, err = nreadUint32(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case Fid:
			var x Fid
			x, idx, err = nreadFid(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case FileMode:
			var x FileMode
			x, idx, err = nreadFileMode(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case uint64:
			var x uint64
			x, idx, err = nreadUint64(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case string:
			var x string
			x, idx, err = nreadString(b, idx)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(x))
		case []byte:
			var l uint32
			l, idx, err = nreadUint32(b, idx)
			if err != nil {
				return err
			}
			x := make([]byte, l)
			copy(x, b[idx:idx+int(l)])
			idx += int(l)
			f.Set(reflect.ValueOf(x))
		case []string:
			var l uint16
			l, idx, err = nreadUint16(b, idx)
			if err != nil {
				return err
			}
			x := make([]string, l)
			for i := 0; i < int(l); i++ {
				var s string
				s, idx, err = nreadString(b, idx)
				if err != nil {
					return err
				}
				x[i] = s
			}
			f.Set(reflect.ValueOf(x))
		case []Qid:
			var l uint16
			l, idx, err = nreadUint16(b, idx)
			if err != nil {
				return err
			}
			x := make([]Qid, l)
			for i := 0; i < int(l); i++ {
				var q Qid
				q, idx, err = decodeQid(b, idx)
				if err != nil {
					return err
				}
				x[i] = q
			}
			f.Set(reflect.ValueOf(x))
		case [8]uint8:
			var x [8]uint8
			copy(x[:], b[idx:idx+8])
			idx += 8
			f.Set(reflect.ValueOf(x))
		default:
			// BEHOLD: HERE LIES DRAGONS
			k := f.Kind()
			if k != reflect.Interface && k != reflect.Ptr {
				f = f.Addr()
			}

			ft := t.Field(i)
			x, ok := f.Interface().(encoding.BinaryUnmarshaler)
			if !ok {
				return fmt.Errorf("unknown field type: %T", f.Interface())
			}

			var ll uint64
			tag := ft.Tag.Get("len")
			switch tag {
			case "uint8":
				var l uint8
				l, idx, err = nreadByte(b, idx)
				if err != nil {
					return err
				}
				ll = uint64(l)
			case "uint16":
				var l uint16
				l, idx, err = nreadUint16(b, idx)
				if err != nil {
					return err
				}
				ll = uint64(l)
			case "uint32":
				var l uint32
				l, idx, err = nreadUint32(b, idx)
				if err != nil {
					return err
				}
				ll = uint64(l)
			case "uint64":
				var l uint64
				l, idx, err = nreadUint64(b, idx)
				if err != nil {
					return err
				}
				ll = uint64(l)
			default:
				if tag == "" {
					return fmt.Errorf("unknown field type: %T", f.Interface())
				}
				ll, err = strconv.ParseUint(tag, 10, 64)
				if err != nil {
					return err
				}
			}

			err = x.UnmarshalBinary(b[idx : idx+int(ll)])
			if err != nil {
				return err
			}
			idx += int(ll)
		}
	}
	return nil
}

func encodeQid(b []byte, q Qid) []byte {
	b = nwriteQidType(b, q.Type)
	b = nwriteUint32(b, q.Version)
	b = nwriteUint64(b, q.Path)
	return b
}

func encode(m interface{}) ([]byte, error) {
	v := reflect.ValueOf(m)
	switch v.Kind() {
	case reflect.Interface, reflect.Ptr:
		v = v.Elem()
	}
	t := v.Type()
	n := v.NumField()
	var b []byte
	for i := 0; i < n; i++ {
		f := v.Field(i)
		switch fv := f.Interface().(type) {
		case uint8:
			b = nwriteByte(b, fv)
		case OpenMode:
			b = nwriteOpenMode(b, fv)
		case uint16:
			b = nwriteUint16(b, fv)
		case Tag:
			b = nwriteTag(b, fv)
		case uint32:
			b = nwriteUint32(b, fv)
		case Fid:
			b = nwriteFid(b, fv)
		case FileMode:
			b = nwriteFileMode(b, fv)
		case uint64:
			b = nwriteUint64(b, fv)
		case string:
			b = nwriteString(b, fv)
		case Qid:
			b = encodeQid(b, fv)
		case []byte:
			b = nwriteUint32(b, uint32(len(fv)))
			b = append(b, fv...)
		case []string:
			b = nwriteUint16(b, uint16(len(fv)))
			for i := range fv {
				b = nwriteString(b, fv[i])
			}
		case []Qid:
			b = nwriteUint16(b, uint16(len(fv)))
			for i := range fv {
				b = encodeQid(b, fv[i])
			}
		case [8]uint8:
			b = append(b, fv[:]...)
		default:
			// BEHOLD: HERE LIES DRAGONS
			k := f.Kind()
			if k == reflect.Struct {
				f = f.Addr()
			}

			ft := t.Field(i)
			x, ok := f.Interface().(encoding.BinaryMarshaler)
			if !ok {
				return nil, fmt.Errorf("unknown field type: %T", fv)
			}
			y, err := x.MarshalBinary()
			if err != nil {
				return nil, err
			}

			tag := ft.Tag.Get("len")
			switch tag {
			case "uint8":
				b = nwriteByte(b, uint8(len(y)))
			case "uint16":
				b = nwriteUint16(b, uint16(len(y)))
			case "uint32":
				b = nwriteUint32(b, uint32(len(y)))
			case "uint64":
				b = nwriteUint64(b, uint64(len(y)))
			case "":
				return nil, fmt.Errorf("field of type %T missing len", fv)
			}
			b = append(b, y...)
		}
	}
	return b, nil
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

	if err = decode(b, m); err != nil {
		return nil, err
	}

	/*	if err = m.UnmarshalBinary(b); err != nil {
		return nil, err
	}*/
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
	/*	if b, err = m.MarshalBinary(); err != nil {
		return err
	}*/
	if b, err = encode(m); err != nil {
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
