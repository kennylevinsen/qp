package qp

// nineP2000 implements the conversions for 9P2000.u.
type nineP2000Dotu struct{}

// Message returns an empty Message based on the provided message type for
// 9P2000.u.
func (nineP2000Dotu) Message(mt MessageType) (Message, error) {
	switch mt {
	case Tauth:
		return &AuthRequestDotu{}, nil
	case Tattach:
		return &AttachRequestDotu{}, nil
	case Rerror:
		return &ErrorResponseDotu{}, nil
	case Tcreate:
		return &CreateRequestDotu{}, nil
	case Rstat:
		return &StatResponseDotu{}, nil
	case Twstat:
		return &WriteStatRequestDotu{}, nil
	default:
		return NineP2000.Message(mt)
	}
}

// MessageType returns the message type of a given message for 9P2000.u.
func (nineP2000Dotu) MessageType(d Message) (MessageType, error) {
	switch d.(type) {
	case *AuthRequestDotu:
		return Tauth, nil
	case *AttachRequestDotu:
		return Tattach, nil
	case *ErrorResponseDotu:
		return Rerror, nil
	case *CreateRequestDotu:
		return Tcreate, nil
	case *StatResponseDotu:
		return Rstat, nil
	case *WriteStatRequestDotu:
		return Twstat, nil
	default:
		return NineP2000.MessageType(d)
	}
}
