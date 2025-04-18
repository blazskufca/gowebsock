package internal

import (
	"errors"
	"unicode/utf8"
)

// TextFrame creates a complete text frame (FIN=1) with the given message
func TextFrame(message string, isServer bool) (*Frame, error) {
	if !utf8.ValidString(message) {
		return nil, errors.New("can not create text frame with invalid UTF-8 in application data")
	}
	if isServer {
		return NewServerFrame(true, OpText, []byte(message))
	}
	return NewClientFrame(true, OpText, []byte(message))
}

// BinaryFrame creates a complete binary frame (FIN=1) with the given data
func BinaryFrame(data []byte, isServer bool) (*Frame, error) {
	if isServer {
		return NewServerFrame(true, OpBinary, data)
	}
	return NewClientFrame(true, OpBinary, data)
}

// FragmentedFrames splits a message into multiple frames with the appropriate FIN and OpCode settings
// maxFrameSize specifies the maximum payload size for each frame
// opcode should be OpText or OpBinary for the first frame
func FragmentedFrames(data []byte, maxFrameSize int, opcode Opcode, isServer bool) ([]*Frame, error) {
	if maxFrameSize <= 0 {
		return nil, errors.New("maxFrameSize must be greater than zero")
	}

	if opcode != OpText && opcode != OpBinary {
		return nil, errors.New("initial opcode must be OpText or OpBinary")
	}

	totalLength := len(data)
	if totalLength == 0 {
		if isServer {
			frame, err := NewClientFrame(true, opcode, []byte{})
			return []*Frame{frame}, err
		} else {
			frame, err := NewServerFrame(true, opcode, []byte{})
			return []*Frame{frame}, err
		}
	}

	numFrames := (totalLength + maxFrameSize - 1) / maxFrameSize
	frames := make([]*Frame, numFrames)

	for i := 0; i < numFrames; i++ {
		start := i * maxFrameSize
		end := start + maxFrameSize
		if end > totalLength {
			end = totalLength
		}

		chunk := data[start:end]
		isFinal := i == numFrames-1
		frameOpcode := opcode

		if i > 0 {

			frameOpcode = OpContinuation
		}

		var err error
		if isServer {
			frames[i], err = NewClientFrame(isFinal, frameOpcode, chunk)
		} else {
			frames[i], err = NewServerFrame(isFinal, frameOpcode, chunk)
		}

		if err != nil {
			return nil, err
		}
	}

	return frames, nil
}
