package proxy

import (
	"context"
	"crypto/ecdsa"
)

// 实际 go-nethernet Dialer 生成的断言必须能被适配器验签；观察不可用仍允许媒体通行。
type netherNetInteropObserver struct {
	key    *ecdsa.PublicKey
	result chan error
}

func (v *netherNetInteropObserver) VerifyOffer(_ context.Context, raw []byte) (netherNetIdentityObservation, error) {
	offer, err := parseNetherNetIdentityOffer(raw)
	if err == nil {
		err = verifyNetherNetFingerprintAssertion(offer, v.key)
	}
	v.result <- err
	return netherNetIdentityObservation{Status: "unavailable", ReasonCode: "trusted_service_unavailable"}, nil
}
