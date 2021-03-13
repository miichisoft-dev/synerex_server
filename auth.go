package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	api "github.com/synerex/synerex_api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

const (
	PublicKeyPath = "./config/public.key"
	PrivateKeyPath = "./config/private.key"
)

// validToken validate hmac MD5 token
func validToken(auth *api.OAuthRequest) error {
	if len(auth.Token) == 0 {
		log.Println("hmac token is required")
		return status.Errorf(codes.Unavailable, "token is required")
	}
	publicKey := os.Getenv("SX_PUBLIC_KEY")
	privateKey := os.Getenv("SX_PRIVATE_KEY")
	key := []byte(publicKey + privateKey)
	message := []byte(auth.NodeId + auth.Time)
	mac := hmac.New(md5.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	token := fmt.Sprintf("%x", expectedMAC)
	if token != auth.Token {
		log.Printf("token not match. token: %s, expected token: %s", auth.Token, token)
		return status.Errorf(codes.PermissionDenied, "token not match")
	}
	return nil
}

// getRsaPrivateKey read private key from file and parse to rsa private key
func getRsaPrivateKey(path string) (*rsa.PrivateKey, error) {
	signBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Println("read file error", err)
		return nil, err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		log.Println("parse rsa key fail", err)
		return nil, err
	}

	return signKey, nil
}

// generateAccessToken generates and signs a new access token
func generateAccessToken(nodeId string) (string, error) {
	if len(nodeId) == 0 {
		return "", status.Errorf(codes.PermissionDenied, "node id is required")
	}

	signKey, err := getRsaPrivateKey(PrivateKeyPath)
	if err != nil {
		return "", err
	}

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	claims["nodeId"] = nodeId
	claims["scope"] = [1]string{"*"}
	claims["role"] = "user"
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()

	accessToken, err := token.SignedString(signKey)
	if err != nil {
		log.Println("sign token fail", err)
		return "", err
	}

	return accessToken, nil
}

// verify verifies the access token string and return a user claim if the token is valid
func verify(accessToken, publicKey string) (string, error) {
	verifyBytes, err := ioutil.ReadFile(publicKey)
	if err != nil {
		log.Println("read file error", err)
		return "", err
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Println("get verify key fail", err)
		return "", err
	}

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (i interface{}, err error) {
		return verifyKey, nil
	})
	if err != nil {
		log.Println("parse token fail", err)
		return "", err
	}
	claims := token.Claims.(jwt.MapClaims)
	role, ok := claims["role"].(string)
	if !ok {
		log.Println("invalid access token, role invalid", role)
		return "", errors.New("invalid access token")
	}

	return role, nil
}

const (
	// BearerSchema is Bearer token schema
	BearerSchema string = "Bearer "
)

func accessibleRoles() map[string][]string {
	return map[string][]string{
		"NotifyDemand":       {"user"},
		"ProposeDemand":      {"user"},
		"NotifySupply":       {"user"},
		"ProposeSupply":      {"user"},
		"SelectSupply":       {"user"},
		"Confirm":            {"user"},
		"SelectDemand":       {"user"},
		"SendMsg":            {"user"},
		"SubscribeDemand":    {"user"},
		"SubscribeSupply":    {"user"},
		"CreateMbus":         {"user"},
		"CloseMbus":          {"user"},
		"SubscribeMbus":      {"user"},
		"SendMbusMsg":        {"user"},
		"GetMbusState":       {"user"},
		"SubscribeGateway":   {"user"},
		"ForwardToGateway":   {"user"},
		"CloseDemandChannel": {"user"},
		"CloseSupplyChannel": {"user"},
		"CloseAllChannels":   {"user"},
	}
}

func authorize(ctx context.Context, method string) error {
	accessibleRoles := accessibleRoles()
	roles, ok := accessibleRoles[method]
	if !ok {
		// everyone can access
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Println("metadata", md)
		return status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	if !strings.HasPrefix(values[0], BearerSchema) {
		return errors.New("authorization requires Basic/Bearer scheme")
	}

	accessToken := values[0][len(BearerSchema):]
	role, err := verify(accessToken, PublicKeyPath)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "access token is invalid: %v", err)
	}

	for _, r := range roles {
		if r == role {
			return nil
		}
	}

	return status.Errorf(codes.PermissionDenied, "no permission to access this RPC")
}
