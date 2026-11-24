// Annotated rule tests: read by opengrep, not compiled (types are stubs).
//go:build ignore

package logic_test

import (
	"crypto/hmac"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
)

// ---- check-then-act-balance-race

func withdrawUnsafe(acc *Account, amount int64) error {
	// ruleid: scp.go.logic.check-then-act-balance-race
	if acc.Balance < amount {
		return ErrInsufficient
	}
	acc.Balance -= amount
	return db.Save(acc).Error
}

func withdrawLocked(mu *sync.Mutex, acc *Account, amount int64) error {
	mu.Lock()
	defer mu.Unlock()
	// ok: scp.go.logic.check-then-act-balance-race
	if acc.Balance < amount {
		return ErrInsufficient
	}
	acc.Balance -= amount
	return db.Save(acc).Error
}

// ---- mass-assignment-db-model

func updateProfileUnsafe(c *gin.Context) {
	var user User
	c.ShouldBindJSON(&user)
	// ruleid: scp.go.logic.mass-assignment-db-model
	db.Save(&user)
}

func updateProfileSafe(c *gin.Context) {
	var input UpdateProfileDTO
	c.ShouldBindJSON(&input)
	user := User{DisplayName: input.DisplayName}
	// ok: scp.go.logic.mass-assignment-db-model
	db.Save(&user)
}

// ---- weak-prng-otp-or-token

func generateOTP() string {
	// ruleid: scp.go.logic.weak-prng-otp-or-token
	otpCode := fmt.Sprintf("%06d", rand.Intn(1000000))
	return otpCode
}

func pickJitter() int {
	// ok: scp.go.logic.weak-prng-otp-or-token
	jitterMs := rand.Intn(500)
	return jitterMs
}

func generateSecureToken() []byte {
	buf := make([]byte, 32)
	// ok: scp.go.logic.weak-prng-otp-or-token
	_, _ = crand.Read(buf)
	return buf
}

// ---- trust-spoofable-identity-header

func handlerHeaders(r *http.Request) {
	// ruleid: scp.go.logic.trust-spoofable-identity-header
	uid := r.Header.Get("X-User-Id")
	// ruleid: scp.go.logic.trust-spoofable-identity-header
	role := r.Header.Get("X-Role")
	// ok: scp.go.logic.trust-spoofable-identity-header
	reqID := r.Header.Get("X-Request-Id")
	_, _, _ = uid, role, reqID
}

// ---- unbounded-pagination-limit

func listOrdersUnsafe(c *gin.Context) {
	raw := c.Query("limit")
	limit, _ := strconv.Atoi(raw)
	// ruleid: scp.go.logic.unbounded-pagination-limit
	db.Limit(limit).Find(&orders)
}

func listOrdersSafe(c *gin.Context) {
	raw := c.Query("limit")
	limit, _ := strconv.Atoi(raw)
	if limit > 100 {
		limit = 100
	}
	// ok: scp.go.logic.unbounded-pagination-limit
	db.Limit(limit).Find(&orders)
}

// ---- non-constant-time-token-compare

func verifyWebhookUnsafe(expectedSignature, got string) bool {
	// ruleid: scp.go.logic.non-constant-time-token-compare
	return expectedSignature == got
}

func verifyWebhookSafe(expectedSignature, got []byte) bool {
	// ok: scp.go.logic.non-constant-time-token-compare
	if expectedSignature == nil {
		return false
	}
	// ok: scp.go.logic.non-constant-time-token-compare
	return hmac.Equal(expectedSignature, got)
}

var _ = json.Unmarshal
