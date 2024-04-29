package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-resty/resty/v2"
	"github.com/palomachain/concord/config"
	"github.com/palomachain/concord/types"
)

const cSignedMessagePrefix = "\x19Ethereum Signed Message:\n32"

func main() {
	log.SetOutput(os.Stdout)
	log.Println("👷 Setting up whisper...")

	cfgPath, url, err := parseArgs()
	if err != nil {
		log.Fatalf("😿 %v", err)
	}

	cfg := getConfig(cfgPath)
	ethCfg := getEthConfig(cfg)
	signer := newSigner(ethCfg)

	log.Println("✅ Done!")

	go run(signer, url)

	// Listen for termination signals
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	<-signalCh

	fmt.Println("\n👋 GG")
}

func parseArgs() (string, string, error) {
	if len(os.Args) != 3 {
		return "", "", fmt.Errorf("expected exactly 2 arguments")
	}

	return os.Args[1], os.Args[2], nil
}

func run(s *Signer, u string) {
	icons := []string{"🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚", "🕛"}
	idx := 0
	spinnerTicker := time.NewTicker(time.Millisecond * 500)
	updateTicker := time.NewTicker(time.Minute)

	// initial query
	update(s, u)

	fmt.Printf("%s Monitoring messages to sign...", icons[idx])
	for {
		select {
		case <-spinnerTicker.C:
			idx++
			if idx > len(icons)-1 {
				idx = 0
			}
			fmt.Printf("\r%s Monitoring messages to sign...", icons[idx])
		case <-updateTicker.C:
			spinnerTicker.Stop()
			update(s, u)
			spinnerTicker.Reset(time.Millisecond * 500)
		}
	}
}

func update(signer *Signer, url string) {
	r := resty.New()
	var msgsToSign []types.QueuedMessage
	if _, err := r.R().SetPathParam("id", signer.addr.Hex()).SetResult(&msgsToSign).Get(url + "/signer/{id}/messages"); err != nil {
		log.Fatalf("failed to query messages: %v", err)
	}

	if len(msgsToSign) < 1 {
		return
	}

	log.Printf("\nFound %d messages ...\n", len(msgsToSign))
	for _, v := range msgsToSign {
		log.Printf("Signing message %v...\n", v.ID)
		signMessage(signer, url, v, r)
	}
}

func signMessage(signer *Signer, url string, msg types.QueuedMessage, r *resty.Client) {
	// calculate signature using private key
	msgBytes := crypto.Keccak256(
		append(
			[]byte(cSignedMessagePrefix),
			msg.BytesToSign...,
		),
	)
	sig, err := signer.sign(msgBytes)
	if err != nil {
		log.Fatal("failed to sign bytes: %w", err)
	}

	if !verifySignature(msg.BytesToSign, sig, signer.addr.Bytes()) {
		log.Fatal("failed to verify signature.")
	}

	signedMsg := types.SignedQueuedMessage{
		QueuedMessage:   msg,
		Signature:       sig,
		SignedByAddress: signer.addr.Hex(),
	}

	if _, err := r.R().SetBody(&signedMsg).Post(url + "/signature"); err != nil {
		log.Fatalf("failed to post signature: %v", err)
	}

	log.Printf("Signature sent for msg %d!\n", msg.ID)
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

func getConfig(path string) *config.Config {
	path = config.Filepath(path).Path()
	fi, err := os.Stat(path)
	if err != nil {
		panic(fmt.Sprintf("couldn't find config file: %v", err))
	}
	if fi.IsDir() {
		panic("path must be a file, not a directory")
	}

	file, err := os.Open(path)
	if err != nil {
		panic(fmt.Sprintf("failed to open config file: %v", err))
	}
	defer file.Close()
	cnf, err := config.FromReader(file)
	if err != nil {
		panic(fmt.Sprintf("couldn't read config file: %v", err))
	}

	if len(cnf.Paloma.ValidatorKey) < 1 {
		cnf.Paloma.ValidatorKey = cnf.Paloma.SigningKey
	}

	return cnf
}

func getEthConfig(cfg *config.Config) *config.EVM {
	for k, v := range cfg.EVM {
		if k == "eth-main" {
			return &v
		}
	}

	panic("no configuration for eth-main found.")
}

type Signer struct {
	addr     ethcommon.Address
	keystore *keystore.KeyStore
}

func newSigner(cfg *config.EVM) *Signer {
	s := &Signer{}
	if !ethcommon.IsHexAddress(cfg.SigningKey) {
		panic("invalid signing address")
	}
	s.addr = ethcommon.HexToAddress(cfg.SigningKey)
	s.keystore = keystore.NewKeyStore(cfg.KeyringDirectory.Path(), keystore.StandardScryptN, keystore.StandardScryptP)

	if !s.keystore.HasAddress(s.addr) {
		panic("address not found in keystore")
	}
	acc := accounts.Account{Address: s.addr}

	if err := s.keystore.Unlock(acc, config.KeyringPassword(cfg.KeyringPassEnvName)); err != nil {
		panic(fmt.Sprintf("failed to unlock account with keystore: %w", err))
	}

	return s
}

func (s Signer) sign(bytes []byte) ([]byte, error) {
	return s.keystore.SignHash(
		accounts.Account{Address: s.addr},
		bytes,
	)
}
