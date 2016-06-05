package greenlight

var (
	// RSAPublicKey for signing JWT Tokens
	RSAPublicKey string

	// RSAPrivateKey for verifying JWT Tokens
	RSAPrivateKey string

	// ECCPublicKey for signing JWT Tokens
	ECCPublicKey string

	// ECCPrivateKey for verifying JWT Tokens
	ECCPrivateKey string
)

const (
	// RS256 is the constant string for selecting a JWT signgin method
	RS256 = "RS256"

	// RS384 is the constant string for selecting a JWT signgin method
	RS384 = "RS384"

	// RS512 is the constant string for selecting a JWT signgin method
	RS512 = "RS512"

	// PS256 is the constant string for selecting a JWT signgin method
	PS256 = "PS256"

	// PS384 is the constant string for selecting a JWT signgin method
	PS384 = "PS384"

	// PS512 is the constant string for selecting a JWT signgin method
	PS512 = "PS512"

	// ES256 is the constant string for selecting a JWT signgin method
	ES256 = "ES256"

	// ES384 is the constant string for selecting a JWT signgin method
	ES384 = "ES384"

	// ES512 is the constant string for selecting a JWT signgin method
	ES512 = "ES512"

	// HS256 is the constant string for selecting a JWT signgin method
	HS256 = "HS256"

	// HS384 is the constant string for selecting a JWT signgin method
	HS384 = "HS384"

	// HS512 is the constant string for selecting a JWT signgin method
	HS512 = "HS512"
)
