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

	googleInAppPurchasePubKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMzgsJOZzyZvmOG8T9baGxDR/DWx6dgku7UdDfc6aGKthPGYouOa4KvLGEuNd+YTilwtEEryi3mmYAtl8MNtiAQCiry7HjdRNle8lLUHSKwBLVCswY3WGEAuW+5mo/V6X0klS8se65fIqCv2x/SKjtTZvKO/Oe3uehREMY1b8uWLrD5roubXzmaLsFGIRi5wdg8UWRe639LCNb2ghD2Uw0svBTJqn/ymsPmCfVjmCNNRDxfxzlA8O4EEKCK1qOdwIejMAfFMrN87u+0HTQbCKQ/xUQrR6fUhWT2mqttBGhi1NmTNBlUDyXYU+7ILbfJUVqQcKNDbFQd+xv9wBnXAhwIDAQAB"
	message := `{"orderId":"GPA.3306-7591-0398-81065","packageName":"tech.pylons.wallet","productId":"free_pylons","purchaseTime":1654615777799,"purchaseState":0,"purchaseToken":"cbejaahehaalippbalkpbdli.AO-J1OyEOB7m9ZzlFq_ChJprKL6TzIfnyrge0rklyT2tQGdy7ETk4F-xxmCTBYyGUMyqZY0TiZVqeKvCc7Y5eNQDOjgILTkovw","acknowledged":false}`
	encodedBase64Digest := base64.StdEncoding.EncodeToString([]byte(message))
	signature := "O90FTzVlKiwRMasg0tgEF65tXoQi7BKOoA8K+2i1SuC0Mbi49Tw7JJAK6bHVXMqGn/urkANCJl1+Zu3vabp91SPLpT1hlVwzAC2NIRa5qs7D7DgAZiaRhqqP+01LNc3DKzxGWVThzT6Cq4PB0h2LyYDlZZBfGFXH9LAXd4e+lNTgewAs1zmBzWBDdFO1G8S7xxB373MgW9V9/rKZH1odyDaMBhbvhMgunmxdtmO6/MOuxkdg2FjvUxXzPTAmnUvoLEM2771caP5JAYxQNeejj2Te1QCTWZ1F66MIggJLEBBqq7sIafGRJ4zKHtpJyhR8iSKatzXcHrXMqUSqTs/W9Q=="
	// msg := &MsgGoogleInAppPurchaseGetCoins{ReceiptDataBase64: encodedBase64Digest, Signature: signature}
	// coinIssuer := CoinIssuer{GoogleInAppPurchasePubKey: googleInAppPurchasePubKey}

	//signature := "O90FTzVlKiwRMasg0tgEF65tXoQi7BKOoA8K+2i1SuC0Mbi49Tw7JJAK6bHVXMqGn/urkANCJl1+Zu3vabp91SPLpT1hlVwzAC2NIRa5qs7D7DgAZiaRhqqP+01LNc3DKzxGWVThzT6Cq4PB0h2LyYDlZZBfGFXH9LAXd4e+lNTgewAs1zmBzWBDdFO1G8S7xxB373MgW9V9/rKZH1odyDaMBhbvhMgunmxdtmO6/MOuxkdg2FjvUxXzPTAmnUvoLEM2771caP5JAYxQNeejj2Te1QCTWZ1F66MIggJLEBBqq7sIafGRJ4zKHtpJyhR8iSKatzXcHrXMqUSqTs/W9Q=="
	//	reciept64 := "eyJvcmRlcklkIjoiR1BBLjMzMDYtNzU5MS0wMzk4LTgxMDY1IiwicGFja2FnZU5hbWUiOiJ0ZWNoLnB5bG9ucy53YWxsZXQiLCJwcm9kdWN0SWQiOiJmcmVlX3B5bG9ucyIsInB1cmNoYXNlVGltZSI6MTY1NDYxNTc3Nzc5OSwicHVyY2hhc2VTdGF0ZSI6MCwicHVyY2hhc2VUb2tlbiI6ImNiZWphYWhlaGFhbGlwcGJhbGtwYmRsaS5BTy1KMU95RU9CN205WnpsRnFfQ2hKcHJLTDZUeklmbnlyZ2UwcmtseVQydFFHZHk3RVRrNEYteHhtQ1RCWXlHVU15cVpZMFRpWlZxZUt2Q2M3WTVlTlFET2pnSUxUa292dyIsImFja25vd2xlZGdlZCI6ZmFsc2V9"

	msg := &MsgGoogleInAppPurchaseGetCoins{ReceiptDataBase64: encodedBase64Digest, Signature: signature}
	coinIssuer := CoinIssuer{GoogleInAppPurchasePubKey: googleInAppPurchasePubKey}

	tests := []struct {
		name       string
		coinIssuer CoinIssuer
		msg        *MsgGoogleInAppPurchaseGetCoins
		wantErr    bool
	}{
		{"valid purchase", coinIssuer, msg, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantErr, ValidateGoogleIAPSignature(msg, tt.coinIssuer) != nil)
		})
	}
}

func TestValidateGoogleIAPSignatureStatic1(t *testing.T) {

	signature := "O90FTzVlKiwRMasg0tgEF65tXoQi7BKOoA8K+2i1SuC0Mbi49Tw7JJAK6bHVXMqGn/urkANCJl1+Zu3vabp91SPLpT1hlVwzAC2NIRa5qs7D7DgAZiaRhqqP+01LNc3DKzxGWVThzT6Cq4PB0h2LyYDlZZBfGFXH9LAXd4e+lNTgewAs1zmBzWBDdFO1G8S7xxB373MgW9V9/rKZH1odyDaMBhbvhMgunmxdtmO6/MOuxkdg2FjvUxXzPTAmnUvoLEM2771caP5JAYxQNeejj2Te1QCTWZ1F66MIggJLEBBqq7sIafGRJ4zKHtpJyhR8iSKatzXcHrXMqUSqTs/W9Q=="
	reciept64 := "eyJvcmRlcklkIjoiR1BBLjMzMDYtNzU5MS0wMzk4LTgxMDY1IiwicGFja2FnZU5hbWUiOiJ0ZWNoLnB5bG9ucy53YWxsZXQiLCJwcm9kdWN0SWQiOiJmcmVlX3B5bG9ucyIsInB1cmNoYXNlVGltZSI6MTY1NDYxNTc3Nzc5OSwicHVyY2hhc2VTdGF0ZSI6MCwicHVyY2hhc2VUb2tlbiI6ImNiZWphYWhlaGFhbGlwcGJhbGtwYmRsaS5BTy1KMU95RU9CN205WnpsRnFfQ2hKcHJLTDZUeklmbnlyZ2UwcmtseVQydFFHZHk3RVRrNEYteHhtQ1RCWXlHVU15cVpZMFRpWlZxZUt2Q2M3WTVlTlFET2pnSUxUa292dyIsImFja25vd2xlZGdlZCI6ZmFsc2V9"

	msg := &MsgGoogleInAppPurchaseGetCoins{ReceiptDataBase64: reciept64, Signature: signature}
	coinIssuer := CoinIssuer{GoogleInAppPurchasePubKey: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMzgsJOZzyZvmOG8T9baGxDR/DWx6dgku7UdDfc6aGKthPGYouOa4KvLGEuNd+YTilwtEEryi3mmYAtl8MNtiAQCiry7HjdRNle8lLUHSKwBLVCswY3WGEAuW+5mo/V6X0klS8se65fIqCv2x/SKjtTZvKO/Oe3uehREMY1b8uWLrD5roubXzmaLsFGIRi5wdg8UWRe639LCNb2ghD2Uw0svBTJqn/ymsPmCfVjmCNNRDxfxzlA8O4EEKCK1qOdwIejMAfFMrN87u+0HTQbCKQ/xUQrR6fUhWT2mqttBGhi1NmTNBlUDyXYU+7ILbfJUVqQcKNDbFQd+xv9wBnXAhwIDAQAB"}
	err := ValidateGoogleIAPSignature(msg, coinIssuer)
	if err != nil {
		t.Fail()
	}

}
