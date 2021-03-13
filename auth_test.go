package main

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	api "github.com/synerex/synerex_api"
	"google.golang.org/grpc/metadata"
	"testing"
	"time"
)

func TestValidToken(t *testing.T)  {
	auth := &api.OAuthRequest{
		NodeId:               "",
		Time:                 "",
		PublicKey:            "",
		Token:                "",
	}

	err := validToken(auth)
	if err == nil || err.Error() != "rpc error: code = Unavailable desc = token is required" {
		t.Errorf("valid Token fail, expected Unavailable error, got %v", err)
	}

	auth.NodeId = "1"
	auth.Time = "2021/03/01 15:30:00"
	auth.Token = "1234567890"
	err = validToken(auth)
	if err == nil || err.Error() != "rpc error: code = PermissionDenied desc = token not match" {
		t.Errorf("valid Token fail, expected PermissionDenied error, got %v", err)
	}

	auth.Token = "ce977846b410395a1d8c979097e9c43b"
	err = validToken(auth)
	if err != nil {
		t.Errorf("valid Token fail, expected nil, got %v", err)
	}
}

func TestGetRsaPrivateKey(t *testing.T) {
	path := "./test/private.key"
	signKey, err := getRsaPrivateKey(path)
	if err == nil || signKey != nil || err.Error() != "open ./test/private.key: no such file or directory" {
		t.Errorf("GetRsaPrivateKey fail, expected no such file or directory , got %v", err)
	}

	path = "auth.go"
	signKey, err = getRsaPrivateKey(path)
	if err == nil || signKey != nil || err.Error() != "Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key" {
		t.Errorf("GetRsaPrivateKey fail, expected Key must be PEM encoded PKCS1 or PKCS8 private key, got %v", err)
	}

	signKey, err = getRsaPrivateKey(PrivateKeyPath)
	if err != nil {
		t.Errorf("GetRsaPrivateKey fail, expected nil, got %v", err)
	}
}

func TestGenerateAccessToken(t *testing.T) {
	accessToken, err := generateAccessToken("")
	if err == nil || len(accessToken) > 0 || err.Error() != "rpc error: code = PermissionDenied desc = node id is required" {
		t.Errorf("generateAccessToken fail, expected PermissionDenied , got %v", err)
	}
	accessToken, err = generateAccessToken("1")
	if err != nil {
		t.Errorf("generateAccessToken fail, expected nil, got %v", err)
	}
}

func TestVerify(t *testing.T) {
	accessToken := ""
	path := ""
	role, err := verify(accessToken, path)
	if err == nil || len(role) > 0 || err.Error() != "open : no such file or directory" {
		t.Errorf("verify fail, expected no such file or directory, got %v", err)
	}

	path = "auth.go"
	role, err = verify(accessToken, path)
	if err == nil || len(role) > 0 || err.Error() != "Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key" {
		t.Errorf("verify fail, expected Invalid Key, got %v", err)
	}

	role, err = verify(accessToken, PublicKeyPath)
	if err == nil || len(role) > 0 || err.Error() != "token contains an invalid number of segments" {
		t.Errorf("verify fail, expected Invalid Key, got %v", err)
	}

	accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTQ1ODMwMTIsImlhdCI6MTYxNDU4MzAxMCwibmJmIjoxNjE0NTgzMDEwLCJub2RlSWQiOiIyIiwicm9sZSI6InVzZXIiLCJzY29wZSI6WyIqIl19.HoojFyXnpfe5oyidv4J_USxPLxsbl5IlttbKrmxmDqvLvihoDJGY7bbotmL4bZA2o5AX8lBUkjXgWvIVObAf_OOvWwuNtVQ8PCnpJBgBVFWmLvwCyrSnZs6XlIOMC74gaEeP66b2pnHqu_mwZLx5uATpQlW9Ln2eLTcTfHQuGXakVyzWD6Jlslfm2H1L_qZzpQB-l-ExdKV3myMSNl_0qBA5iM2jKtF1fG8kGkVcxX-TiZKFPIgj1y2EbLtIAXIOquqzKVOWXd4EGrFmHEv8EZNXb6BIUm3sRuRU27_VQRT9zZF5GBgKvTKuRY9CicbpsD7Fy2G5Fd_XPrDswGDIPw"
	role, err = verify(accessToken, PublicKeyPath)
	if err == nil || len(role) > 0 || err.Error() != "Token is expired" {
		t.Errorf("verify fail, expected nil, got %v", err)
	}

	signKey, _ := getRsaPrivateKey(PrivateKeyPath)
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	claims["nodeId"] = "1"
	claims["scope"] = [1]string{"*"}
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	accessToken, _ = token.SignedString(signKey)
	role, err = verify(accessToken, PublicKeyPath)
	if err == nil || len(role) > 0 || err.Error() != "invalid access token" {
		t.Errorf("verify fail, expected invalid access token, got %v", err)
	}

	signKey, _ = getRsaPrivateKey(PrivateKeyPath)
	token = jwt.New(jwt.SigningMethodRS256)
	claims = token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	claims["nodeId"] = "1"
	claims["scope"] = [1]string{"*"}
	claims["role"] = "admin"
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	accessToken, _ = token.SignedString(signKey)
	role, err = verify(accessToken, PublicKeyPath)
	if role != "admin" {
		t.Errorf("verify fail, expected admin, got %v", role)
	}

	accessToken, err = generateAccessToken("2")
	role, err = verify(accessToken, PublicKeyPath)
	if err != nil || role != "user" {
		t.Errorf("verify fail, expected nil, got %v", err)
	}
}

func TestAccessibleRoles(t *testing.T) {
	roles := accessibleRoles()
	role, ok := roles["NotifyDemand"]
	if !ok {
		t.Errorf("accessibleRoles fail, expected user, got %s", role)
	}
}

func TestAuthorize(t *testing.T) {
	err := authorize(context.Background(), "GetAccessToken")
	if err != nil {
		t.Errorf("authorize fail, expected nil, got %v", err)
	}

	err = authorize(context.Background(), "NotifyDemand")
	if err == nil || err.Error() != "rpc error: code = Unauthenticated desc = metadata is not provided" {
		t.Errorf("authorize fail, expected Unauthenticated desc = metadata, got %v", err)
	}

	simpleCtx, _ := context.WithTimeout(context.TODO(), 2*time.Second)
	accessToken, _ := generateAccessToken("2")
	md := metadata.Pairs("access_token", fmt.Sprintf("%s%v", BearerSchema, accessToken))
	ctx := metautils.NiceMD(md).ToIncoming(simpleCtx)

	err = authorize(ctx, "NotifyDemand")
	if err == nil || err.Error() != "rpc error: code = Unauthenticated desc = authorization token is not provided" {
		t.Errorf("authorize fail, expected Unauthenticated desc = authorization, got %v", err)
	}

	md = metadata.Pairs("authorization", fmt.Sprintf("%s%v", "", accessToken))
	ctx = metautils.NiceMD(md).ToIncoming(simpleCtx)
	err = authorize(ctx, "NotifyDemand")
	if err == nil || err.Error() != "authorization requires Basic/Bearer scheme" {
		t.Errorf("authorize fail, expected authorization requires Basic/Bearer scheme, got %v", err)
	}

	md = metadata.Pairs("authorization", fmt.Sprintf("%s%v", BearerSchema, "bad token"))
	ctx = metautils.NiceMD(md).ToIncoming(simpleCtx)
	err = authorize(ctx, "NotifyDemand")
	if err == nil || err.Error() != "rpc error: code = Unauthenticated desc = access token is invalid: token contains an invalid number of segments" {
		t.Errorf("authorize fail, expected access token is invalid, got %v", err)
	}

	md = metadata.Pairs("authorization", fmt.Sprintf("%s%v", BearerSchema, accessToken))
	ctx = metautils.NiceMD(md).ToIncoming(simpleCtx)
	err = authorize(ctx, "NotifyDemand")
	if err != nil {
		t.Errorf("authorize fail, expected nil, got %v", err)
	}

	signKey, _ := getRsaPrivateKey(PrivateKeyPath)
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	claims["nodeId"] = "1"
	claims["scope"] = [1]string{"*"}
	claims["role"] = "admin"
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	accessToken, _ = token.SignedString(signKey)
	md = metadata.Pairs("authorization", fmt.Sprintf("%s%v", BearerSchema, accessToken))
	ctx = metautils.NiceMD(md).ToIncoming(simpleCtx)
	err = authorize(ctx, "NotifyDemand")
	if err == nil || err.Error() != "rpc error: code = PermissionDenied desc = no permission to access this RPC" {
		t.Errorf("authorize fail, expected PermissionDenied, got %v", err)
	}
}