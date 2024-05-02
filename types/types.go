package types

import (
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
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
	// ValAddress      sdk.ValAddress
	Signature       []byte
	SignedByAddress string
	// PublicKey       []byte
}

type MessageWithSignatures struct {
	Signatures []ValidatorSignature
	QueuedMessage
}

type Valset struct {
	Snapshot Snapshot
}

type Snapshot struct {
	Id          uint64
	Height      uint64
	Validators  []Validator
	TotalShares uint64
}

type Validator struct {
	ShareCount         uint64
	State              string
	Address            string
	ExternalChainInfos []ExternalChainInfos
}

type ExternalChainInfos struct {
	ChainReferenceID string
	Address          string
	Pubkey           string
}

type Signature struct {
	V *big.Int
	R *big.Int
	S *big.Int
}
type CompassValset struct {
	ValsetId   *big.Int
	Validators []ethcommon.Address
	Powers     []*big.Int
}
type CompassConsensus struct {
	Valset     CompassValset
	Signatures []Signature
}

type CompassLogicCallArgs struct {
	Payload              []byte
	LogicContractAddress ethcommon.Address
}
