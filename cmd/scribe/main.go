package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/palomachain/concord/config"
	"github.com/palomachain/concord/types"
	evmtypes "github.com/palomachain/paloma/x/evm/types"
	"github.com/syndtr/goleveldb/leveldb"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	// Last observed message ID on target chain compass + 1000
	// See: https://etherscan.io/tx/0x81263ea3145ad2a4a846d5c9f1ee7d434e5ddbebb90c5dd3098b402d8cfb9a67
	cMessageID uint64 = 467095 + 1000

	// Base64 notation of the deployed compass unqiue ID
	cSmartContractUniqueIDAsBase64 string = "ODg3MjMwOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	// Chain reference ID of the target chain this message will be relayed to.
	cChainReferenceID string = "eth-main"

	// Address of deployed compass on Ethereum mainnet for chain ID
	// messenger.
	// See: https://etherscan.io/address/0xB01cC20Fe02723d43822819ec57fCbadf31f1537
	cCompassAddress string = "0xB01cC20Fe02723d43822819ec57fCbadf31f1537"

	// Operator address for the VolumeFi validator,
	// in charge of manually relaying this message upon
	// finished signature collection.
	// See: https://paloma.explorers.guru/validator/palomavaloper1wm4y8yhppxud6j5wvwr7fyynhh09tmv5fy845g
	cVolumeFiOperatorAddress string = "palomavaloper1wm4y8yhppxud6j5wvwr7fyynhh09tmv5fy845g"

	// Last observed blockheight of used snapshot
	// https://download.palomachain.com/paloma_15681076.tar.lz4
	cLastSnapshotBlockheight int64 = 15681076

	// TargetContractAddress to which to relay to
	cTargetContractAddress = "0x34bc9970228b14a76ebf0a7f5a601001bbca20c8"
)

func main() {
	if printVersion() {
		return
	}

	msgId, payload, err := parseArgs()
	if err != nil {
		log.Fatalf("failed to parse args: %v", err)
	}

	fmt.Println("Adding new message...")
	msg := constructMessage(msgId, payload)
	newpath := filepath.Join(".", "data")
	if err := os.MkdirAll(newpath, os.ModePerm); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}

	db, err := leveldb.OpenFile(fmt.Sprintf("./data/%v.db", msg.ID), nil)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}

	bz, err := bson.Marshal(msg)
	if err != nil {
		log.Fatalf("bson.Marhal: %v", err)
	}

	if err := db.Put([]byte("msg"), bz, nil); err != nil {
		log.Fatalf("failed to persist message: %v", err)
	}

	fmt.Println("🎉 Done!")
}

func constructMessage(msgId uint64, payload string) types.QueuedMessage {
	// Turnstone ID is the unique ID of the target smart contract
	// It's available as b64 notation string from within the snapshot used
	// But is stored as direct string cast of the underlaying byte slice
	// when constructing this message.
	// See: https://github.com/palomachain/paloma/blob/e1433cb86bc94b6bf51fda38898384ebd52add52/x/evm/keeper/keeper.go#L619
	turnstoneID, err := base64.StdEncoding.DecodeString(cSmartContractUniqueIDAsBase64)
	if err != nil {
		log.Fatal("failed to parse smart contract unique ID:", err)
	}

	// Nonce is identical to message ID, but wrapped into []byte
	// see: https://github.com/palomachain/paloma/blob/e1433cb86bc94b6bf51fda38898384ebd52add52/x/consensus/keeper/concensus_keeper.go#L644
	nonce := sdk.Uint64ToBigEndian(cMessageID)

	payloadBz, err := hexutil.Decode(payload)
	if err != nil {
		log.Fatal("failed to parse payload bytes:", err)
	}

	deadline := time.Now().UTC().Add(time.Hour * 1).Unix()
	bytesToSign, err := packBytesToSign(string(turnstoneID), payloadBz, msgId, deadline)
	if err != nil {
		log.Fatal("failed to pack bytes to sign:", err)
	}

	return types.QueuedMessage{
		ID:               msgId,
		Nonce:            nonce,
		BytesToSign:      bytesToSign,
		PublicAccessData: nil,
		ErrorData:        nil,
		Msg: &evmtypes.Message{
			TurnstoneID:      string(turnstoneID),
			ChainReferenceID: cChainReferenceID,
			Action: &evmtypes.Message_SubmitLogicCall{
				SubmitLogicCall: &evmtypes.SubmitLogicCall{
					HexContractAddress: cTargetContractAddress,
					Payload:            payloadBz,
					Deadline:           deadline,
				},
			},
			CompassAddr:           cCompassAddress,
			Assignee:              cVolumeFiOperatorAddress,
			AssignedAtBlockHeight: math.NewInt(cLastSnapshotBlockheight),
		},
	}
}

func printVersion() bool {
	if len(os.Args) < 2 || os.Args[1] != "version" {
		return false
	}

	fmt.Printf("Scribe\nVersion: %s\nCommit: %s\n", config.Version(), config.Commit())
	return true
}

func parseArgs() (uint64, string, error) {
	if len(os.Args) != 3 {
		return 0, "", fmt.Errorf("expected exactly 2 arguments")
	}

	id, err := strconv.ParseUint(os.Args[1], 10, 64)
	return id, os.Args[2], err
}

func mustType[T any](val T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("failed to create type: %v", err))
	}
	return val
}

func packBytesToSign(turnstoneID string, payload []byte, msgID uint64, deadline int64) ([]byte, error) {
	arguments := abi.Arguments{
		{Type: mustType(abi.NewType("tuple", "", []abi.ArgumentMarshaling{
			{Name: "address", Type: "address"},
			{Name: "payload", Type: "bytes"},
		}))},
		{Type: mustType(abi.NewType("uint256", "", nil))},
		{Type: mustType(abi.NewType("bytes32", "", nil))},
		{Type: mustType(abi.NewType("uint256", "", nil))},
	}

	method := abi.NewMethod("logic_call", "logic_call", abi.Function, "", false, false, arguments, abi.Arguments{})
	var bytes32 [32]byte
	copy(bytes32[:], turnstoneID)

	// confirmed: turnstoneID is correct here
	bytes, err := arguments.Pack(
		struct {
			Address ethcommon.Address
			Payload []byte
		}{
			ethcommon.HexToAddress(cTargetContractAddress),
			payload,
		},
		new(big.Int).SetUint64(msgID),
		bytes32,
		new(big.Int).SetInt64(deadline),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack logic_call args: %w", err)
	}

	bytes = append(method.ID[:], bytes...)

	return crypto.Keccak256(bytes), nil
}
