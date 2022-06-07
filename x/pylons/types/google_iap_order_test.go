package types

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec
	"crypto/x509"
	"encoding/base64"
	fmt "fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateGoogleIAPSignature(t *testing.T) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Error(fmt.Printf("rsa.GenerateKey: %v\n", err))
		t.Fail()

	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	googleInAppPurchasePubKey := base64.StdEncoding.EncodeToString(pubBytes)

	message := "{\"orderId\":\"GPA.3394-4112-7048-14805\",\"packageName\":\"tech.pylons.wallet\",\"productId\":\"free_pylons\",\"purchaseTime\":1653891466961,\"purchaseState\":0,\"purchaseToken\":\"eafhleeolclclafkfmmcidoj.AO-J1OxuhZCjvZC7qmYxXCQFDAsrQ2FAot8PHgd9Gt0Ag_-U9ZCzao6EdkDBhxWGfQFqwV9PZNx5sW-WMrv5KfYS1g4K-mhDAA\",\"acknowledged\":false}"
	messageBytes := bytes.NewBufferString(message)
	hash := sha1.New()
	hash.Write(messageBytes.Bytes())
	digest := hash.Sum(nil)

	encodedBase64Digest := base64.StdEncoding.EncodeToString([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, digest)
	if err != nil {
		t.Error(fmt.Printf("rsa.SignPKCS1v15 error: %v\n", err))
		t.Fail()
	}

	signaturebase64Encoded := base64.StdEncoding.EncodeToString(signature)
	tests := []struct {
		name       string
		coinIssuer CoinIssuer
		msg        *MsgGoogleInAppPurchaseGetCoins
		wantErr    bool
	}{
		{"valid purchase", CoinIssuer{GoogleInAppPurchasePubKey: googleInAppPurchasePubKey}, &MsgGoogleInAppPurchaseGetCoins{ReceiptDataBase64: encodedBase64Digest, Signature: signaturebase64Encoded}, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantErr, ValidateGoogleIAPSignature(tt.msg, tt.coinIssuer) != nil)
		})
	}
}

func TestValidateGoogleIAPSignatureStatic(t *testing.T) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Error(fmt.Printf("rsa.GenerateKey: %v\n", err))
		t.Fail()

	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	googleInAppPurchasePubKey := base64.StdEncoding.EncodeToString(pubBytes)

	message := "{\"orderId\":\"GPA.3394-4112-7048-14805\",\"packageName\":\"tech.pylons.wallet\",\"productId\":\"free_pylons\",\"purchaseTime\":1653891466961,\"purchaseState\":0,\"purchaseToken\":\"eafhleeolclclafkfmmcidoj.AO-J1OxuhZCjvZC7qmYxXCQFDAsrQ2FAot8PHgd9Gt0Ag_-U9ZCzao6EdkDBhxWGfQFqwV9PZNx5sW-WMrv5KfYS1g4K-mhDAA\",\"acknowledged\":false}"
	messageBytes := bytes.NewBufferString(message)
	hash := sha1.New()
	hash.Write(messageBytes.Bytes())
	digest := hash.Sum(nil)

	encodedBase64Digest := base64.StdEncoding.EncodeToString([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, digest)
	if err != nil {
		t.Error(fmt.Printf("rsa.SignPKCS1v15 error: %v\n", err))
		t.Fail()
	}

	signaturebase64Encoded := base64.StdEncoding.EncodeToString(signature)
	tests := []struct {
		name       string
		coinIssuer CoinIssuer
		msg        *MsgGoogleInAppPurchaseGetCoins
		wantErr    bool
	}{
		{"valid purchase", CoinIssuer{GoogleInAppPurchasePubKey: googleInAppPurchasePubKey}, &MsgGoogleInAppPurchaseGetCoins{ReceiptDataBase64: encodedBase64Digest, Signature: signaturebase64Encoded}, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantErr, ValidateGoogleIAPSignature(tt.msg, tt.coinIssuer) != nil)
		})
	}
}
