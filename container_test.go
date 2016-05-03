package qp

import (
	"bytes"
	"io"
	"testing"
	"time"
)

const reruns = 1000

// ByteReader is a read that only reads a single byte at a time.
type ByteReader struct {
	io.Reader
}

func (b *ByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return b.Reader.Read(p[0:1])
}

func TestDecoder(t *testing.T) {
	// Prepare the input

	inputbuf := new(bytes.Buffer)
	r := &ByteReader{Reader: inputbuf}

	// We write the 9P test-set reruns' times to have a decent amount of data.
	for y := 0; y < reruns; y++ {
		for _, tt := range MessageTestData {
			inputbuf.Write(tt.container)
		}
	}

	provided := inputbuf.Len()

	// Prepare decoder
	d := Decoder{
		Protocol:    NineP2000,
		Reader:      r,
		MessageSize: 1024,
	}
	d.Reset()

	// Run decoder

	//  Time limit
	donech := make(chan bool, 1)
	go func() {
		select {
		case <-time.After(5 * time.Second):
			t.Errorf("decoder never terminated: %d bytes read, %d bytes provided", provided-inputbuf.Len(), provided)
		case <-donech:
		}
	}()

	for y := 0; y < reruns; y++ {
		for i := range MessageTestData {
			mtd := MessageTestData[i].input
			m, err := d.ReadMessage()
			if err != nil {
				t.Fatalf("test %dx%d: failed on %T with error: %v", y, i, mtd, err)
			}
			if !CompareMarshallables(mtd, m) {
				t.Errorf("test %dx%d: failed on %T\n\tExpected: %#v\n\tGot:      %#v", y, i, mtd, mtd, m)
			}
		}
	}

	donech <- true

	if inputbuf.Len() > 0 {
		t.Errorf("buffer has unread data: %d bytes read, %d bytes provided", provided-inputbuf.Len(), provided)
	}
}

func TestDecoderGreedy(t *testing.T) {
	// Prepare the input

	inputbuf := new(bytes.Buffer)
	r := &ByteReader{Reader: inputbuf}

	// We write the 9P test-set reruns' times to have a decent amount of data.
	for y := 0; y < reruns; y++ {
		for _, tt := range MessageTestData {
			inputbuf.Write(tt.container)
		}
	}

	provided := inputbuf.Len()

	// Prepare decoder
	d := Decoder{
		Protocol:    NineP2000,
		Reader:      r,
		MessageSize: 1024,
		Greedy:      true,
	}
	d.Reset()

	// Run decoder

	//  Time limit
	donech := make(chan bool, 1)
	go func() {
		select {
		case <-time.After(5 * time.Second):
			t.Errorf("decoder never terminated: %d bytes read, %d bytes provided", provided-inputbuf.Len(), provided)
		case <-donech:
		}
	}()

	for y := 0; y < reruns; y++ {
		for i := range MessageTestData {
			mtd := MessageTestData[i].input
			m, err := d.ReadMessage()
			if err != nil {
				t.Fatalf("test %dx%d: failed on %T with error: %v", y, i, mtd, err)
			}
			if !CompareMarshallables(mtd, m) {
				t.Errorf("test %dx%d: failed on %T\n\tExpected: %#v\n\tGot:      %#v", y, i, mtd, mtd, m)
			}
		}
	}

	donech <- true

	if inputbuf.Len() > 0 {
		t.Errorf("buffer has unread data: %d bytes read, %d bytes provided", provided-inputbuf.Len(), provided)
	}
}

func TestEncoder(t *testing.T) {
	buf := new(bytes.Buffer)
	e := Encoder{
		Protocol:    NineP2000,
		Writer:      buf,
		MessageSize: 1024,
	}

	// We write the 9P test-set reruns' times to have a decent amount of data.
	for y := 0; y < reruns; y++ {
		for _, tt := range MessageTestData {
			err := e.WriteMessage(tt.input)
			if err != nil {
				t.Fatalf("unable to write to buffer: %v", err)
			}
		}
	}

	x := buf.Bytes()

	for y := 0; y < reruns; y++ {
		for i, v := range MessageTestData {
			length := len(v.container)
			if len(x) < length {
				t.Fatalf("test %dx%d: not enough data written to read %T: Expected %d, got %d", y, i, v.input, length, len(x))
			}

			segment := x[:length]
			x = x[length:]

			if bytes.Compare(segment, v.container) != 0 {
				t.Errorf("test %dx%d: encoded message did not match reference.\nExpected: %#v\n\tGot:      %#v", y, i, v.container, segment)
			}
		}
	}
}
