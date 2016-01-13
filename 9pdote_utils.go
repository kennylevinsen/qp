package qp

// nineP2000 implements the conversions for 9P2000.e.
type nineP2000Dote struct{}

// Message returns an empty Message based on the provided message type for
// 9P2000.e.
func (nineP2000Dote) Message(mt MessageType) (Message, error) {
	switch mt {
	case Tsession:
		return &SessionRequestDote{}, nil
	case Rsession:
		return &SessionResponseDote{}, nil
	case Tsread:
		return &SimpleReadRequestDote{}, nil
	case Rsread:
		return &SimpleReadResponseDote{}, nil
	case Tswrite:
		return &SimpleWriteRequestDote{}, nil
	case Rswrite:
		return &SimpleWriteResponseDote{}, nil
	default:
		return NineP2000.Message(mt)
	}
}

// MessageType returns the message type of a given message for 9P2000.e.
func (nineP2000Dote) MessageType(d Message) (MessageType, error) {
	switch d.(type) {
	case *SessionRequestDote:
		return Tsession, nil
	case *SessionResponseDote:
		return Rsession, nil
	case *SimpleReadRequestDote:
		return Tsread, nil
	case *SimpleReadResponseDote:
		return Rsread, nil
	case *SimpleWriteRequestDote:
		return Tswrite, nil
	case *SimpleWriteResponseDote:
		return Rswrite, nil
	default:
		return NineP2000.MessageType(d)
	}
}
