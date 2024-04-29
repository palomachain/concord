package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type QueuedMessage struct {
	Msg              any
	Nonce            []byte
	BytesToSign      []byte
	PublicAccessData []byte
	ErrorData        []byte
	ID               uint64
}

type SignedQueuedMessage struct {
	SignedByAddress string
	Signature       []byte
	QueuedMessage
}

type ValidatorSignature struct {
	ValAddress      sdk.ValAddress
	Signature       []byte
	SignedByAddress string
	PublicKey       []byte
}

type MessageWithSignatures struct {
	Signatures []ValidatorSignature
	QueuedMessage
}
