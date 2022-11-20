package pgp

import "fmt"

// UserID represents a human-readable user identity.
type UserID struct {
	Name  string
	Email string
}

func (id *UserID) Encode() []byte {
	if id.Email == "" {
		return []byte(id.Name)
	}
	if id.Name == "" {
		return []byte(id.Email)
	}

	return []byte(fmt.Sprintf("%s <%s>", id.Name, id.Email))
}

func (id *UserID) EncodePacket() []byte {
	return EncodePacket(PacketTagUserID, id.Encode())
}
