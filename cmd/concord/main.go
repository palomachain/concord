package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	evmtypes "github.com/palomachain/paloma/x/evm/types"
	"github.com/palomachain/pigeon/chain"
	"github.com/syndtr/goleveldb/leveldb"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	// Last observed message ID on target chain compass + 1000
	// See: https://etherscan.io/tx/0x81263ea3145ad2a4a846d5c9f1ee7d434e5ddbebb90c5dd3098b402d8cfb9a67
	cMessageID uint64 = 467095 + 1002

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

	cSignedMessagePrefix = "\x19Ethereum Signed Message:\n32"
)

type dba struct {
	p map[string]*leveldb.DB
}

type SigningInfo struct {
	SignedByAddress string
	Signature       string
}

type MessageWithSigners struct {
	Message chain.QueuedMessage
	Signers []SigningInfo
}

func main() {
	log.SetOutput(os.Stdout)
	slog.Info("Server startup...")

	if populate() {
		return
	}

	db := newDb()
	if err := db.scan(); err != nil {
		log.Fatalf("Failed to scan stores: %v", err)
	}
	defer db.close()

	router := http.NewServeMux()

	router.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router.HandleFunc("GET /messages", func(w http.ResponseWriter, _ *http.Request) {
		msgs := make([]MessageWithSigners, 0, len(db.p))
		for key, store := range db.p {
			mws, err := getMsgWithSignersFromStore(store)
			if err != nil {
				slog.With("msg-id", key).With("error", err).Warn("Failed to get message from store.")
			}
			msgs = append(msgs, mws)
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(msgs)
	})

	router.HandleFunc("GET /message/{id}", func(w http.ResponseWriter, r *http.Request) {
		msgId, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			slog.With("error", err).Warn("Failed to parse message ID.")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		store, fnd := db.p[r.PathValue("id")]
		if !fnd {
			slog.With("msg-id", msgId).Warn("Unknown message ID.")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		msg, err := getMsgWithSignersFromStore(store)
		if err != nil {
			slog.With("error", err).With("msg-id", msgId).Warn("Failed to get message from store.")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(msg)
	})

	router.HandleFunc("GET /signer/{id}/messages", func(w http.ResponseWriter, r *http.Request) {
		signer := r.PathValue("id")
		if !ethcommon.IsHexAddress(signer) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		msgsToSign := make([]chain.QueuedMessage, 0, len(db.p))
		signerAddress := ethcommon.HexToAddress(signer)
		for key, store := range db.p {
			_, err := store.Get(signerAddress.Bytes(), nil)
			if err == nil {
				// Looks like this message was already signed.
				continue
			}

			if err != leveldb.ErrNotFound {
				slog.With("msg-id", key).With("error", err).Warn("Failed to get signer from store.")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			msg, err := getMsgFromStore(store)
			if err != nil {
				slog.With("msg-id", key).With("error", err).Warn("Failed to get message from store.")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			msgsToSign = append(msgsToSign, msg)
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(msgsToSign)
	})

	router.HandleFunc("POST /signature", func(w http.ResponseWriter, r *http.Request) {
		var signedMessage chain.SignedQueuedMessage
		if err := json.NewDecoder(r.Body).Decode(&signedMessage); err != nil {
			slog.With("error", err).Warn("Failed to decode json.")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		key := fmt.Sprintf("%d", signedMessage.ID)
		if _, found := db.p[key]; !found {
			slog.With("msg-id", signedMessage.ID).With("signer", signedMessage.SignedByAddress).Warn("Unknown message ID.")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		addr, err := hexutil.Decode(signedMessage.SignedByAddress)
		if err != nil {
			slog.With("error", err).With("msg-id", signedMessage.ID).With("signer", signedMessage.SignedByAddress).Warn("Failed to parse SignedByAddress.")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if _, err := db.p[key].Get(addr, nil); err == nil {
			slog.With("msg-id", signedMessage.ID).With("signer", signedMessage.SignedByAddress).Warn("Duplicate signature received.")
			w.WriteHeader(http.StatusConflict)
			return
		}

		if !verifySignature(signedMessage.BytesToSign, signedMessage.Signature, addr) {
			slog.With("msg-id", signedMessage.ID).Warn("Failed to verify signature.")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		slog.With("msg-id", signedMessage.ID).With("signer", signedMessage.SignedByAddress).Info("Received signature.")
		if err := db.p[key].Put(addr, signedMessage.Signature, nil); err != nil {
			slog.With("msg-id", signedMessage.ID).With("signer", signedMessage.SignedByAddress).With("error", err).Warn("Failed to store signature.")
		}
	})

	http.ListenAndServe(":8080", router)
}

func verifySignature(msg, sig, address []byte) bool {
	receivedAddr := ethcommon.BytesToAddress(address)

	bytesToVerify := crypto.Keccak256(append(
		[]byte(cSignedMessagePrefix),
		msg...,
	))
	recoveredPk, err := crypto.Ecrecover(bytesToVerify, sig)
	if err != nil {
		return false
	}
	pk, err := crypto.UnmarshalPubkey(recoveredPk)
	if err != nil {
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*pk)
	return receivedAddr.Hex() == recoveredAddr.Hex()
}

func newDb() *dba {
	return &dba{
		p: make(map[string]*leveldb.DB),
	}
}

func (d *dba) scan() error {
	files, err := os.ReadDir("./data")
	if err != nil {
		return err
	}

	for _, item := range files {
		if !item.IsDir() {
			continue
		}

		if len(item.Name()) < 3 || item.Name()[len(item.Name())-3:] != ".db" {
			continue
		}

		name := strings.TrimSuffix(filepath.Base(item.Name()), filepath.Ext(item.Name()))

		if _, found := d.p[name]; found {
			continue
		}

		slog.With("msg-id", item.Name()).Info("Found new message.")
		d.p[name], err = leveldb.OpenFile("./data/"+item.Name(), nil)
		if err != nil {
			slog.With("msg-id", item.Name()).With("error", err).Warn("Failed to open store.")
		}
	}
	return nil
}

func (d *dba) close() {
	for _, v := range d.p {
		v.Close()
	}
}

func populate() bool {
	if len(os.Args) < 2 || os.Args[1] != "populate" {
		return false
	}

	msg := constructMessage()
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

	db.Put([]byte("msg"), bz, nil)

	return true
}

func getMsgFromStore(store *leveldb.DB) (chain.QueuedMessage, error) {
	msgBz, err := store.Get([]byte("msg"), nil)
	if err != nil {
		return chain.QueuedMessage{}, fmt.Errorf("failed to get message from store: %w", err)
	}

	var msg chain.QueuedMessage
	if err := bson.Unmarshal(msgBz, &msg); err != nil {
		return chain.QueuedMessage{}, fmt.Errorf("failed to unmarshal serialized message: %w", err)
	}

	return msg, nil
}

func getMsgWithSignersFromStore(store *leveldb.DB) (MessageWithSigners, error) {
	msg, err := getMsgFromStore(store)
	if err != nil {
		return MessageWithSigners{}, fmt.Errorf("failed to get message from store: %v", err)
	}

	mws := MessageWithSigners{Message: msg, Signers: make([]SigningInfo, 0, 64)}
	iter := store.NewIterator(nil, nil)
	for iter.Next() {
		if string(iter.Key()) == "msg" {
			continue
		}

		addr := ethcommon.BytesToAddress(iter.Key())
		sig := ethcommon.Bytes2Hex(iter.Value())
		mws.Signers = append(mws.Signers, SigningInfo{
			SignedByAddress: addr.Hex(),
			Signature:       sig,
		})
	}

	return mws, nil
}

func constructMessage() chain.QueuedMessage {
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

	bytes, err := hexutil.Decode("0xfdca5e1f000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000d3e576b5dcde3580420a5ef78f3639ba9cd1b9670000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000b49dea7d6af04bd085ee67c528488f15af2559b54a5207693f678d4f4a355aa63da3979e804cadb2")
	if err != nil {
		log.Fatal("failed to parse payload bytes:", err)
	}

	return chain.QueuedMessage{
		ID:               cMessageID,
		Nonce:            nonce,
		BytesToSign:      bytes,
		PublicAccessData: nil,
		ErrorData:        nil,
		Msg: &evmtypes.Message{
			TurnstoneID:      string(turnstoneID),
			ChainReferenceID: cChainReferenceID,
			Action: &evmtypes.Message_SubmitLogicCall{
				SubmitLogicCall: &evmtypes.SubmitLogicCall{},
			},
			CompassAddr:           cCompassAddress,
			Assignee:              cVolumeFiOperatorAddress,
			AssignedAtBlockHeight: math.NewInt(cLastSnapshotBlockheight),
		},
	}
}
