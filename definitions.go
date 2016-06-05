package greenlight

import ()

type JWTDefinition struct {
	Token      string
	Expiration int
	TokenType  string
}

type UserDefinition struct {
	GivenName    string
	Surname      string
	Email        string
	PasswordHash string
	PasswordSalt string
}
