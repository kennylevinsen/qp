package qp

import "errors"

// ErrUnknownMessageType is used to indicate an unknown type of message.
var ErrUnknownMessageType = errors.New("unknown message type")

// nineP2000 implements the conversions for 9P2000.
type nineP2000 struct{}

// Message returns an empty Message based on the provided message type.
func (nineP2000) Message(mt MessageType) (Message, error) {
	switch mt {
	case Tversion:
		return &VersionRequest{}, nil
	case Rversion:
		return &VersionResponse{}, nil
	case Tauth:
		return &AuthRequest{}, nil
	case Rauth:
		return &AuthResponse{}, nil
	case Tattach:
		return &AttachRequest{}, nil
	case Rattach:
		return &AttachResponse{}, nil
	case Tflush:
		return &FlushRequest{}, nil
	case Rflush:
		return &FlushResponse{}, nil
	case Twalk:
		return &WalkRequest{}, nil
	case Rwalk:
		return &WalkResponse{}, nil
	case Topen:
		return &OpenRequest{}, nil
	case Ropen:
		return &OpenResponse{}, nil
	case Tcreate:
		return &CreateRequest{}, nil
	case Rcreate:
		return &CreateResponse{}, nil
	case Tread:
		return &ReadRequest{}, nil
	case Rread:
		return &ReadResponse{}, nil
	case Twrite:
		return &WriteRequest{}, nil
	case Rwrite:
		return &WriteResponse{}, nil
	case Tclunk:
		return &ClunkRequest{}, nil
	case Rclunk:
		return &ClunkResponse{}, nil
	case Tremove:
		return &RemoveRequest{}, nil
	case Rremove:
		return &RemoveResponse{}, nil
	case Tstat:
		return &StatRequest{}, nil
	case Rstat:
		return &StatResponse{}, nil
	case Twstat:
		return &WriteStatRequest{}, nil
	case Rwstat:
		return &WriteStatResponse{}, nil
	case Rerror:
		return &ErrorResponse{}, nil
	default:
		return nil, ErrUnknownMessageType
	}
}

// MessageType returns the message type of a given message.
func (nineP2000) MessageType(d Message) (MessageType, error) {
	switch d.(type) {
	case *VersionRequest:
		return Tversion, nil
	case *VersionResponse:
		return Rversion, nil
	case *AuthRequest:
		return Tauth, nil
	case *AuthResponse:
		return Rauth, nil
	case *AttachRequest:
		return Tattach, nil
	case *AttachResponse:
		return Rattach, nil
	case *ErrorResponse:
		return Rerror, nil
	case *FlushRequest:
		return Tflush, nil
	case *FlushResponse:
		return Rflush, nil
	case *WalkRequest:
		return Twalk, nil
	case *WalkResponse:
		return Rwalk, nil
	case *OpenRequest:
		return Topen, nil
	case *OpenResponse:
		return Ropen, nil
	case *CreateRequest:
		return Tcreate, nil
	case *CreateResponse:
		return Rcreate, nil
	case *ReadRequest:
		return Tread, nil
	case *ReadResponse:
		return Rread, nil
	case *WriteRequest:
		return Twrite, nil
	case *WriteResponse:
		return Rwrite, nil
	case *ClunkRequest:
		return Tclunk, nil
	case *ClunkResponse:
		return Rclunk, nil
	case *RemoveRequest:
		return Tremove, nil
	case *RemoveResponse:
		return Rremove, nil
	case *StatRequest:
		return Tstat, nil
	case *StatResponse:
		return Rstat, nil
	case *WriteStatRequest:
		return Twstat, nil
	case *WriteStatResponse:
		return Rwstat, nil
	default:
		return 0, ErrUnknownMessageType
	}
}
