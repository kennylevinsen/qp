package qp

import (
	"encoding/binary"
	"errors"
)

var ErrPayloadTooShort = errors.New("payload too short")

func nreadByte(s []byte, idx int) (b byte, n int, err error) {
	if len(s) < idx+1 {
		return 0, 0, ErrPayloadTooShort
	}
	return s[idx], idx + 1, nil
}

func nwriteByte(s []byte, b byte) []byte {
	return append(s, b)
}

func nreadUint16(s []byte, idx int) (uint16, int, error) {
	if len(s) < idx+2 {
		return 0, 0, ErrPayloadTooShort
	}
	return binary.LittleEndian.Uint16(s[idx : idx+2]), idx + 2, nil
}

func nwriteUint16(s []byte, u uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, u)
	return append(s, b...)
}

func nreadUint32(s []byte, idx int) (uint32, int, error) {
	if len(s) < idx+4 {
		return 0, 0, ErrPayloadTooShort
	}
	return binary.LittleEndian.Uint32(s[idx : idx+4]), idx + 4, nil
}

func nwriteUint32(s []byte, u uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, u)
	return append(s, b...)
}

func nreadUint64(s []byte, idx int) (uint64, int, error) {
	if len(s) < idx+8 {
		return 0, 0, ErrPayloadTooShort
	}
	return binary.LittleEndian.Uint64(s[idx : idx+8]), idx + 8, nil
}

func nwriteUint64(s []byte, u uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, u)
	return append(s, b...)
}

func nreadTag(s []byte, idx int) (Tag, int, error) {
	u, n, err := nreadUint16(s, idx)
	return Tag(u), n, err
}

func nwriteTag(s []byte, t Tag) []byte {
	return nwriteUint16(s, uint16(t))
}

func nreadFid(s []byte, idx int) (Fid, int, error) {
	u, n, err := nreadUint32(s, idx)
	return Fid(u), n, err
}

func nwriteFid(s []byte, t Fid) []byte {
	return nwriteUint32(s, uint32(t))
}

func nreadOpenMode(s []byte, idx int) (OpenMode, int, error) {
	u, n, err := nreadByte(s, idx)
	return OpenMode(u), n, err
}

func nwriteOpenMode(s []byte, o OpenMode) []byte {
	return nwriteByte(s, byte(o))
}

func nreadQidType(s []byte, idx int) (QidType, int, error) {
	u, n, err := nreadByte(s, idx)
	return QidType(u), n, err
}

func nwriteQidType(s []byte, q QidType) []byte {
	return nwriteByte(s, byte(q))
}

func nreadMessageType(s []byte, idx int) (MessageType, int, error) {
	u, n, err := nreadByte(s, idx)
	return MessageType(u), n, err
}

func nwriteMessageType(s []byte, mt MessageType) []byte {
	return nwriteByte(s, byte(mt))
}

func nreadFileMode(s []byte, idx int) (FileMode, int, error) {
	u, n, err := nreadUint32(s, idx)
	return FileMode(u), n, err
}

func nwriteFileMode(s []byte, f FileMode) []byte {
	return nwriteUint32(s, uint32(f))
}

func nreadString(s []byte, idx int) (string, int, error) {
	if len(s) < idx+2 {
		return "", 0, ErrPayloadTooShort
	}

	l := int(binary.LittleEndian.Uint16(s[idx : idx+2]))
	end := idx + 2 + l
	if len(s) < end {
		return "", 0, ErrPayloadTooShort
	}

	return string(s[idx+2 : end]), end, nil
}

func nwriteString(s []byte, str string) []byte {
	b := make([]byte, 2+len(str))
	binary.LittleEndian.PutUint16(b[0:2], uint16(len(str)))
	copy(b[2:], []byte(str))
	return append(s, b...)
}
