package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/palomachain/concord/config"
	"github.com/palomachain/concord/types"
	"github.com/syndtr/goleveldb/leveldb"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	cSignedMessagePrefix = "\x19Ethereum Signed Message:\n32"
)

type dba struct {
	p map[string]struct{}
}

func main() {
	log.SetOutput(os.Stdout)
	if printVersion() {
		return
	}

	slog.With("version", config.Version()).Info("Server startup...")
	db := newDb()
	go db.watch()

	router := http.NewServeMux()

	router.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router.HandleFunc("GET /messages", func(w http.ResponseWriter, _ *http.Request) {
		msgs := make([]types.MessageWithSignatures, 0, len(db.p))
		for key := range db.p {
			store, err := db.getStore(key)
			if err != nil {
				slog.With("msg-id", key).With("error", err).Warn("Failed to open store.")
			}
			defer store.Close()
			mws, err := getMsgWithSignersFromStore(store)
			if err != nil {
				slog.With("msg-id", key).With("error", err).Warn("Failed to get message from store.")
			}
			msgs = append(msgs, mws)
		}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(msgs); err != nil {
			slog.With("error", err).Warn("Failed to encode response.")
		}
	})

	router.HandleFunc("GET /message/{id}", func(w http.ResponseWriter, r *http.Request) {
		msgId, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			slog.With("error", err).Warn("Failed to parse message ID.")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		store, err := db.getStore(r.PathValue("id"))
		if err != nil {
			slog.With("msg-id", msgId).With("error", err).Warn("Unknown message ID.")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer store.Close()

		msg, err := getMsgWithSignersFromStore(store)
		if err != nil {
			slog.With("error", err).With("msg-id", msgId).Warn("Failed to get message from store.")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(msg); err != nil {
			slog.With("error", err).Warn("Failed to encode response.")
		}
	})

	router.HandleFunc("GET /signer/{id}/messages", func(w http.ResponseWriter, r *http.Request) {
		signer := r.PathValue("id")
		if !ethcommon.IsHexAddress(signer) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		msgsToSign := make([]types.QueuedMessage, 0, len(db.p))
		signerAddress := ethcommon.HexToAddress(signer)
		for key := range db.p {
			store, err := db.getStore(key)
			if err != nil {
				slog.With("msg-id", key).With("error", err).Warn("Failed to open store")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer store.Close()
			_, err = store.Get(signerAddress.Bytes(), nil)
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
		if err := json.NewEncoder(w).Encode(msgsToSign); err != nil {
			slog.With("error", err).Warn("Failed to encode response.")
		}
	})

	router.HandleFunc("POST /signature", func(w http.ResponseWriter, r *http.Request) {
		var signedMessage types.SignedQueuedMessage
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

		store, err := db.getStore(key)
		if err != nil {
			slog.With("msg-id", signedMessage.ID).With("signer", signedMessage.SignedByAddress).Warn("Failed to open store.")
			w.WriteHeader(http.StatusConflict)
			return
		}
		defer store.Close()
		if _, err := store.Get(addr, nil); err == nil {
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
		if err := store.Put(addr, signedMessage.Signature, nil); err != nil {
			slog.With("msg-id", signedMessage.ID).With("signer", signedMessage.SignedByAddress).With("error", err).Warn("Failed to store signature.")
		}
	})

	if err := http.ListenAndServe(":8080", router); err != nil {
		slog.With("error", err).Warn("HTTP server failed")
	}

	slog.Info("Goodbye!")
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
		p: make(map[string]struct{}),
	}
}

func (d *dba) watch() {
	watchTicker := time.NewTicker(time.Minute)
	slog.Info("Watching for new messages...")

	// initial query
	if err := d.scan(); err != nil {
		log.Fatalf("failed to watch file system for new messages: %v", err)
	}

	for {
		<-watchTicker.C
		if err := d.scan(); err != nil {
			log.Fatalf("failed to watch file system for new messages: %v", err)
		}
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
		tmpDb, err := leveldb.OpenFile("./data/"+item.Name(), nil)
		if err != nil {
			slog.With("msg-id", item.Name()).With("error", err).Warn("Failed to open store.")
		}
		d.p[name] = struct{}{}
		tmpDb.Close()
	}
	return nil
}

func (d *dba) getStore(key string) (*leveldb.DB, error) {
	if _, fnd := d.p[key]; !fnd {
		return nil, fmt.Errorf("key not found: %v", key)
	}

	return leveldb.OpenFile("./data/"+key+".db", nil)
}

func getMsgFromStore(store *leveldb.DB) (types.QueuedMessage, error) {
	msgBz, err := store.Get([]byte("msg"), nil)
	if err != nil {
		return types.QueuedMessage{}, fmt.Errorf("failed to get message from store: %w", err)
	}

	var msg types.QueuedMessage
	if err := bson.Unmarshal(msgBz, &msg); err != nil {
		return types.QueuedMessage{}, fmt.Errorf("failed to unmarshal serialized message: %w", err)
	}

	return msg, nil
}

func getMsgWithSignersFromStore(store *leveldb.DB) (types.MessageWithSignatures, error) {
	msg, err := getMsgFromStore(store)
	if err != nil {
		return types.MessageWithSignatures{}, fmt.Errorf("failed to get message from store: %v", err)
	}

	mws := types.MessageWithSignatures{QueuedMessage: msg, Signatures: make([]types.ValidatorSignature, 0, 64)}
	iter := store.NewIterator(nil, nil)
	for iter.Next() {
		if string(iter.Key()) == "msg" {
			continue
		}

		addr := ethcommon.BytesToAddress(iter.Key())
		mws.Signatures = append(mws.Signatures, types.ValidatorSignature{
			Signature:       iter.Value(),
			SignedByAddress: addr.Hex(),
		})
	}

	return mws, nil
}

func printVersion() bool {
	if len(os.Args) < 2 || os.Args[1] != "version" {
		return false
	}

	fmt.Printf("Concord\nVersion: %s\nCommit: %s\n", config.Version(), config.Commit())
	return true
}
