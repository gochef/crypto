package crypto

// Crypto is our global crypto object
type Crypto struct {
	Bcrypt *Bcrypt
}

// New initializes and returns the Crypto object
func New() *Crypto {
	return &Crypto{
		Bcrypt: NewBcrypt(),
	}
}
