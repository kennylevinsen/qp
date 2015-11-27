package qp

import "testing"

// Test if the types live up to their interface
var (
	_ codec   = (*StatDotu)(nil)
	_ Message = (*AuthRequestDotu)(nil)
	_ Message = (*AttachRequestDotu)(nil)
	_ Message = (*ErrorResponseDotu)(nil)
	_ Message = (*CreateRequestDotu)(nil)
	_ Message = (*StatResponseDotu)(nil)
	_ Message = (*WriteStatRequestDotu)(nil)
)

// This test does NOT guarantee proper 9P2000 spec coding, but ensures at least
// that all codecs are compatible with themselves.
func TestReencodeDotu(t *testing.T) {
	tests := []struct {
		in codec
	}{
		{
			&StatDotu{
				Type:       0xDEAD,
				Dev:        0xABCDEF08,
				Qid:        Qid{},
				Mode:       FileMode(OTRUNC),
				Atime:      90870987,
				Mtime:      1234124,
				Length:     0x23ABDDF8,
				Name:       "hello",
				UID:        "someone",
				GID:        "over the",
				MUID:       "rainbow",
				Extensions: "hello",
				UIDno:      23452345,
				GIDno:      34652,
				MUIDno:     2363457,
			},
		}, {
			&AuthRequestDotu{
				Tag:      45,
				AuthFid:  Fid(1234),
				Username: "someone",
				Service:  "something",
				UIDno:    3546298,
			},
		}, {
			&AttachRequestDotu{
				Tag:      45,
				Fid:      35243,
				AuthFid:  90872354,
				Username: "",
				Service:  "weee",
				UIDno:    2563457,
			},
		}, {
			&ErrorResponseDotu{
				Tag:   45,
				Error: "something something something",
				Errno: 345324,
			},
		}, {
			&CreateRequestDotu{
				Tag:         45,
				Fid:         12343,
				Name:        "wakakaaka",
				Permissions: DMDIR,
				Mode:        4,
				Extensions:  "qefdasiuh",
			},
		}, {
			&StatResponseDotu{
				Tag:  45,
				Stat: StatDotu{},
			},
		}, {
			&WriteStatRequestDotu{
				Tag:  45,
				Fid:  12342134,
				Stat: StatDotu{},
			},
		},
	}
	for i, tt := range tests {
		reencode(i, tt.in, t, NineP2000Dotu)
	}
}
