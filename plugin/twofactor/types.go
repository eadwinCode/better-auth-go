package twofactor

import "time"

type twoFactorRecord struct {
	ID                      string
	UserID                  string
	Secret                  string
	BackupCodes             string
	Verified                bool
	FailedVerificationCount int
	LockedUntil             *time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type verificationMetadata struct {
	UserID   string `json:"userId,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
	CodeHash string `json:"codeHash,omitempty"`
}

type signInResponse struct {
	Redirect bool `json:"redirect"`
	Token    any  `json:"token"`
	User     struct {
		ID string `json:"id"`
	} `json:"user"`
}
