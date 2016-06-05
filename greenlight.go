package greenlight

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func GetJWTData(request *UserDefinition, method string) (JWTDefinition, error) {
	jwtStruct := JWTDefinition{}
	exp := time.Now().Add(time.Hour * 72).Unix()
	expiration := int(exp)

	signingMethod, err := getAlgorithmType(method)
	if err != nil {
		return jwtStruct, nil
	}

	token := jwt.New(signingMethod)
	token.Claims["exp"] = expiration
	token.Claims["sub"] = ""

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(RSAPrivateKey))
	if err != nil {
		return jwtStruct, err
	}
	tokenStr, err := token.SignedString(key)
	if err != nil {
		return jwtStruct, err
	}

	jwtStruct.Token = tokenStr
	jwtStruct.Expiration = expiration

	return jwtStruct, err
}

func parseKey(method string) (interface{}, error) {
	m := method[0:3]
	switch m {
	case "RS":
		key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(RSAPrivateKey))
		if err != nil {
			return key, err
		}
		return nil, nil
	case "ES":
		key, err := jwt.ParseECPrivateKeyFromPEM([]byte(ECCPrivateKey))
		if err != nil {
			return key, err
		}
		return nil, nil
	default:
		return nil, errors.New("Algorithm doesn not exist")
	}
}

func getAlgorithmType(method string) (jwt.SigningMethod, error) {
	m := method[0:3]
	switch m {
	case "RS":
		signingMethod, err := getRSASigningAlgorithm(method)
		return signingMethod, err
	case "PS":
		signingMethod, err := getPSSigningAlgorithm(method)
		return signingMethod, err
	case "ES":
		signingMethod, err := getECDSASigningAlgorithm(method)
		return signingMethod, err
	case "HS":
		signingMethod, err := getHMACSigningAlgorithm(method)
		return signingMethod, err
	default:
		return nil, errors.New("Algorithm does not exist")
	}
}

func getRSASigningAlgorithm(method string) (*jwt.SigningMethodRSA, error) {
	switch method {
	case RS256:
		return jwt.SigningMethodRS256, nil
	case RS384:
		return jwt.SigningMethodRS384, nil
	case RS512:
		return jwt.SigningMethodRS512, nil
	default:
		return nil, errors.New("RSA signing algorithm does not exist")
	}
}

func getPSSigningAlgorithm(method string) (*jwt.SigningMethodRSAPSS, error) {
	switch method {
	case PS256:
		return jwt.SigningMethodPS256, nil
	case PS384:
		return jwt.SigningMethodPS384, nil
	case PS512:
		return jwt.SigningMethodPS512, nil
	default:
		return nil, errors.New("PSS signing algorithm does not exist")
	}
}

func getECDSASigningAlgorithm(method string) (*jwt.SigningMethodECDSA, error) {
	switch method {
	case ES256:
		return jwt.SigningMethodES256, nil
	case ES384:
		return jwt.SigningMethodES384, nil
	case ES512:
		return jwt.SigningMethodES512, nil
	default:
		return nil, errors.New("ECDSA signing algorithm does not exist")
	}
}

func getHMACSigningAlgorithm(method string) (*jwt.SigningMethodHMAC, error) {
	switch method {
	case HS256:
		return jwt.SigningMethodHS256, nil
	case HS384:
		return jwt.SigningMethodHS384, nil
	case HS512:
		return jwt.SigningMethodHS512, nil
	default:
		return nil, errors.New("HMAC signing algorithm does not exist")
	}
}
