package crypto

import "golang.org/x/crypto/bcrypt"

// Bcrypt struct
type Bcrypt struct {
	cost int
}

// NewBcrypt initializes and returns the bcrypt object
func NewBcrypt() *Bcrypt {
	return &Bcrypt{
		cost: bcrypt.DefaultCost,
	}
}

// SetCost sets the hashing cost to be used
// Usually called just before the make function
func (b *Bcrypt) SetCost(cost int) *Bcrypt {
	b.cost = cost
	return b
}

// Make takes a string, and hashes it with the bcrypt algorithm
// NOTE this uses the default cost of 10
func (b *Bcrypt) Make(password string) (string, error) {
	// Hashing the password with the default cost of 10
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed), err
}

// Check compares a plain string against a hashed string and checks if they are equal
// returns true when equal, false otherwise
func (b *Bcrypt) Check(password, hashedPassword string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err == nil {
		return true
	}
	return false
}
