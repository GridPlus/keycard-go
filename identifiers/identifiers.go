package identifiers

import "errors"

var (
	CardManagerAID = []byte{0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}
	CardTestKey    = []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}

	PackageAID      = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01}
	KeycardAID      = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01}
	NdefAID         = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x02}
	NdefInstanceAID = []byte{0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}

	KeycardDefaultInstanceIndex = 1

	ErrInvalidInstanceIndex = errors.New("instance index must be between 1 and 255")
)

func KeycardInstanceAID(index int) ([]byte, error) {
	if index < 0x01 || index > 0xFF {
		return nil, ErrInvalidInstanceIndex
	}

	return append(KeycardAID, byte(index)), nil
}
