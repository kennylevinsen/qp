package qp

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

type codec interface {
	EncodedLength() int
	Encode(w io.Writer) error
	Decode(r io.Reader) error
}

// Test if the types live up to their interface
var (
	_ codec   = (*Qid)(nil)
	_ codec   = (*Stat)(nil)
	_ Message = (*VersionRequest)(nil)
	_ Message = (*VersionResponse)(nil)
	_ Message = (*AuthRequest)(nil)
	_ Message = (*AuthResponse)(nil)
	_ Message = (*AttachRequest)(nil)
	_ Message = (*AttachResponse)(nil)
	_ Message = (*ErrorResponse)(nil)
	_ Message = (*FlushRequest)(nil)
	_ Message = (*FlushResponse)(nil)
	_ Message = (*WalkRequest)(nil)
	_ Message = (*WalkResponse)(nil)
	_ Message = (*OpenRequest)(nil)
	_ Message = (*OpenResponse)(nil)
	_ Message = (*CreateRequest)(nil)
	_ Message = (*CreateResponse)(nil)
	_ Message = (*ReadRequest)(nil)
	_ Message = (*ReadResponse)(nil)
	_ Message = (*WriteRequest)(nil)
	_ Message = (*WriteResponse)(nil)
	_ Message = (*ClunkRequest)(nil)
	_ Message = (*ClunkResponse)(nil)
	_ Message = (*RemoveRequest)(nil)
	_ Message = (*RemoveResponse)(nil)
	_ Message = (*StatRequest)(nil)
	_ Message = (*StatResponse)(nil)
	_ Message = (*WriteStatRequest)(nil)
	_ Message = (*WriteStatResponse)(nil)
)

func reencode(i int, in codec, t *testing.T, p Protocol) {
	// Magic to get the basic type, not the pointer type
	inputType := reflect.ValueOf(in).Elem().Type()
	var other codec
	buf := new(bytes.Buffer)
	if inm, ok := in.(Message); ok {
		// Full message handling, including length/type wrapper.
		if err := p.Encode(buf, inm); err != nil {
			t.Errorf("test %d: encoding failed for %v: %v", i, inputType, err)
			return
		}

		var err error
		other, err = p.Decode(buf)
		if err != nil {
			t.Errorf("test %d: decoding failed for %v: %v", i, inputType, err)
			return
		}
	} else {
		// Only encode/decode the message part itself.
		other = reflect.New(inputType).Interface().(codec)

		if err := in.Encode(buf); err != nil {
			t.Errorf("test %d: encoding failed for %v: %v", i, inputType, err)
			return
		}

		if err := other.Decode(buf); err != nil {
			t.Errorf("test %d: decoding failed for %v: %v", i, inputType, err)
			return
		}
	}

	// Comparing the interfaces would result in pointer comparisons, so get the basic type first
	if !reflect.DeepEqual(reflect.ValueOf(in).Elem().Interface(), reflect.ValueOf(other).Elem().Interface()) {
		t.Errorf("test %d: %v did not reencode correctly", i, inputType)
	}
}

// This test does NOT guarantee proper 9P2000 spec coding, but ensures at least
// that all codecs are compatible with themselves.
func TestReencode(t *testing.T) {
	tests := []struct {
		in codec
	}{
		{
			&Qid{
				Type:    QTDIR,
				Version: 0x12340987,
				Path:    0x10293874FFFFFF,
			},
		}, {
			&Stat{
				Type:   0xDEAD,
				Dev:    0xABCDEF08,
				Qid:    Qid{},
				Mode:   FileMode(OTRUNC),
				Atime:  90870987,
				Mtime:  1234124,
				Length: 0x23ABDDF8,
				Name:   "hello",
				UID:    "someone",
				GID:    "over the",
				MUID:   "rainbow",
			},
		}, {
			&VersionRequest{
				Tag:     45,
				MaxSize: 9384,
				Version: "9P2000",
			},
		}, {
			&VersionResponse{
				Tag:     45,
				MaxSize: 9384,
				Version: "9P2000",
			},
		}, {
			&AuthRequest{
				Tag:      45,
				AuthFid:  Fid(1234),
				Username: "someone",
				Service:  "something",
			},
		}, {
			&AuthResponse{
				Tag:     45,
				AuthQid: Qid{},
			},
		}, {
			&AttachRequest{
				Tag:      45,
				Fid:      35243,
				AuthFid:  90872354,
				Username: "",
				Service:  "weee",
			},
		}, {
			&AttachResponse{
				Tag: 45,
				Qid: Qid{},
			},
		}, {
			&ErrorResponse{
				Tag:   45,
				Error: "something something something",
			},
		}, {
			&FlushRequest{
				Tag:    45,
				OldTag: 23453,
			},
		}, {
			&FlushResponse{
				Tag: 45,
			},
		}, {
			&WalkRequest{
				Tag:    45,
				Fid:    1234,
				NewFid: 3452345,
				Names: []string{
					"ongo",
					"bongo",
					"filliyonko",
					"megatronko",
				},
			},
		}, {
			&WalkResponse{
				Tag: 45,
				Qids: []Qid{
					{},
					{},
					{},
				},
			},
		}, {
			&OpenRequest{
				Tag:  45,
				Fid:  21343,
				Mode: 4,
			},
		}, {
			&OpenResponse{
				Tag:    45,
				Qid:    Qid{},
				IOUnit: 1234123,
			},
		}, {
			&CreateRequest{
				Tag:         45,
				Fid:         12343,
				Name:        "wakakaaka",
				Permissions: DMDIR,
				Mode:        4,
			},
		}, {
			&CreateResponse{
				Tag:    45,
				Qid:    Qid{},
				IOUnit: 433535,
			},
		}, {
			&ReadRequest{
				Tag:    45,
				Fid:    5343,
				Offset: 359842382234,
				Count:  23423,
			},
		}, {
			&ReadResponse{
				Tag:  45,
				Data: []byte("ooooh nooo it's full of data"),
			},
		}, {
			&WriteRequest{
				Tag:    45,
				Fid:    254334,
				Offset: 21304978234,
				Data:   []byte("something to write"),
			},
		}, {
			&WriteResponse{
				Tag:   45,
				Count: 12,
			},
		}, {
			&ClunkRequest{
				Tag: 45,
				Fid: 23123,
			},
		}, {
			&ClunkResponse{
				Tag: 45,
			},
		}, {
			&RemoveRequest{
				Tag: 45,
				Fid: 1234,
			},
		}, {
			&RemoveResponse{
				Tag: 45,
			},
		}, {
			&StatRequest{
				Tag: 45,
				Fid: 12341234,
			},
		}, {
			&StatResponse{
				Tag:  45,
				Stat: Stat{},
			},
		}, {
			&WriteStatRequest{
				Tag:  45,
				Fid:  12342134,
				Stat: Stat{},
			},
		}, {
			&WriteStatResponse{
				Tag: 45,
			},
		},
	}
	for i, tt := range tests {
		reencode(i, tt.in, t, NineP2000)
	}
}
