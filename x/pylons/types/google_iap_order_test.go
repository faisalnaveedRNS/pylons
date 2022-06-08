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

	googleInAppPurchasePubKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwZsjhk6eN5Pve9pP3uqz2MwBFixvmCRtQJoDQLTEJo3zTd9VMZcXoerQX8cnDPclZWmMZWkO+BWcN1ikYdGHvU2gC7yBLi+TEkhsEkixMlbqOGRdmNptJJhqxuVmXK+drWTb6W0IgQ9g8CuCjZUiMTc0UjHb5mPOE/IhcuTZ0wCHdoqc5FS2spdQqrohvSEP7gR4ZgGzYNI1U+YZHskIEm2qC4ZtSaX9J/fDkAmmJFV2hzeDMcljCxY9+ZM1mdzIpZKwM7O6UdWRpwD1QJ7yXND8AQ9M46p16F0VQuZbbMKCs90NIcKkx6jDDGbVmJrFnUT1Oq1uYxNYtiZjTp+JowIDAQAB"

	message := "{\"orderId\":\"GPA.3306-7591-0398-81065\",\"packageName\":\"tech.pylons.wallet\",\"productId\":\"free_pylons\",\"purchaseTime\":1654615777799,\"purchaseState\":0,\"purchaseToken\":\"cbejaahehaalippbalkpbdli.AO-J1OyEOB7m9ZzlFq_ChJprKL6TzIfnyrge0rklyT2tQGdy7ETk4F-xxmCTBYyGUMyqZY0TiZVqeKvCc7Y5eNQDOjgILTkovw\",\"acknowledged\":false}"
	encodedBase64Digest := base64.StdEncoding.EncodeToString([]byte(message))

	signaturebase64Encoded := "O90FTzVlKiwRMasg0tgEF65tXoQi7BKOoA8K+2i1SuC0Mbi49Tw7JJAK6bHVXMqGn/urkANCJl1+Zu3vabp91SPLpT1hlVwzAC2NIRa5qs7D7DgAZiaRhqqP+01LNc3DKzxGWVThzT6Cq4PB0h2LyYDlZZBfGFXH9LAXd4e+lNTgewAs1zmBzWBDdFO1G8S7xxB373MgW9V9/rKZH1odyDaMBhbvhMgunmxdtmO6/MOuxkdg2FjvUxXzPTAmnUvoLEM2771caP5JAYxQNeejj2Te1QCTWZ1F66MIggJLEBBqq7sIafGRJ4zKHtpJyhR8iSKatzXcHrXMqUSqTs/W9Q==" //base64.StdEncoding.EncodeToString(signature)
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
