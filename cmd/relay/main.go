package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/palomachain/concord/config"
	"github.com/palomachain/concord/types"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const cMaxPower = 1 << 32

func main() {
	log.SetOutput(os.Stdout)
	if printVersion() {
		return
	}

	msgId, cfgPath, url, err := parseArgs()
	if err != nil {
		log.Fatalf("😿 %v", err)
	}

	cfg := getConfig(cfgPath)
	ethCfg := getEthConfig(cfg)
	signer := newSigner(ethCfg)
	client, err := ethclient.Dial(url)
	if err != nil {
		log.Fatalf("Failed to dial to eth RPC: %v", err)
	}

	abi, err := loadABI()
	if err != nil {
		log.Fatalf("Failed to load ABI: %v", err)
	}

	valset, err := parseValset()
	if err != nil {
		log.Fatalf("Failed to load valset: %v", err)
	}

	msg, err := getMsg(msgId)
	if err != nil {
		log.Fatalf("failed to read message: %v", err)
	}

	tx, err := submitLogicCall(msg, valset, client, signer, abi)
	if err != nil {
		log.Fatalf("failed to relay message: %v", err)
	}

	log.Printf("🎉 Message relayed, tx: %v\n", tx.Hash())
}

func getStore(id uint64) (*leveldb.DB, error) {
	path := fmt.Sprintf("./data/%d.db", id)
	if stat, err := os.Stat(path); err != nil || !stat.IsDir() {
		return nil, err
	}

	return leveldb.OpenFile(path, &opt.Options{
		NoSync:   true,
		ReadOnly: true,
	})
}

func parseValset() (*types.Valset, error) {
	fi, err := os.Open("./data/valset.json")
	if err != nil {
		return nil, fmt.Errorf("failed to open valset file: %w", err)
	}
	defer fi.Close()

	bz, err := io.ReadAll(fi)
	if err != nil {
		return nil, fmt.Errorf("failed to read valset file: %w", err)
	}

	var v types.Valset
	if err := json.Unmarshal(bz, &v); err != nil {
		return nil, fmt.Errorf("failed to parse valset: %w", err)
	}

	sort.SliceStable(v.Snapshot.Validators, func(i, j int) bool {
		// doing GTE because we want a reverse sort
		return v.Snapshot.Validators[i].ShareCount >= v.Snapshot.Validators[j].ShareCount
	})

	return &v, nil
}

func getMsg(id uint64) (types.MessageWithSignatures, error) {
	store, err := getStore(id)
	if err != nil {
		return types.MessageWithSignatures{}, fmt.Errorf("failed to open store: %w", err)
	}
	defer store.Close()

	msgBz, err := store.Get([]byte("msg"), nil)
	if err != nil {
		return types.MessageWithSignatures{}, fmt.Errorf("failed to get message from store: %w", err)
	}

	var msg types.QueuedMessage
	if err := bson.Unmarshal(msgBz, &msg); err != nil {
		return types.MessageWithSignatures{}, fmt.Errorf("failed to unmarshal serialized message: %w", err)
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

func submitLogicCall(
	msg types.MessageWithSignatures,
	valset *types.Valset,
	client *ethclient.Client,
	signer *Signer,
	abi abi.ABI,
) (*ethtypes.Transaction, error) {
	d := msg.Msg.(primitive.D)
	compass := (d.Map()["compassaddr"]).(string)
	con := buildCompassConsensus(valset, msg.Signatures)
	compassArgs := types.CompassLogicCallArgs{
		LogicContractAddress: ethcommon.HexToAddress(compass),
		Payload:              msg.BytesToSign,
	}

	args := []any{
		con,
		compassArgs,
		new(big.Int).SetInt64(int64(msg.ID)),
		new(big.Int).SetInt64(time.Now().UTC().Add(time.Minute * 10).Unix()),
	}

	compassAddr := ethcommon.HexToAddress(compass)
	tx, err := callSmartContract("submit_logic_call", args, abi, client, signer.addr, compassAddr, signer.keystore)
	if err != nil {
		return nil, fmt.Errorf("failed to call compass: %w", err)
	}

	return tx, nil
}

func buildCompassConsensus(v *types.Valset, signatures []types.ValidatorSignature) types.CompassConsensus {
	signatureMap := make(map[string]types.ValidatorSignature)
	for _, v := range signatures {
		signatureMap[v.SignedByAddress] = v
	}
	con := types.CompassConsensus{
		Valset: transformValsetToCompassValset(v),
	}

	for i := range v.Snapshot.Validators {
		sig, ok := signatureMap[v.Snapshot.Validators[i].Address]
		if !ok {
			con.Signatures = append(con.Signatures,
				types.Signature{
					V: big.NewInt(0),
					R: big.NewInt(0),
					S: big.NewInt(0),
				})
		} else {
			con.Signatures = append(con.Signatures,
				types.Signature{
					V: new(big.Int).SetInt64(int64(sig.Signature[64]) + 27),
					R: new(big.Int).SetBytes(sig.Signature[:32]),
					S: new(big.Int).SetBytes(sig.Signature[32:64]),
				},
			)
		}
	}

	return con
}

func transformValsetToCompassValset(val *types.Valset) types.CompassValset {
	var cs types.CompassValset

	var totalPower int64 = 0
	for _, val := range val.Snapshot.Validators {
		totalPower += int64(val.ShareCount)
	}

	for _, v := range val.Snapshot.Validators {
		if v.State != "ACTIVE" {
			continue
		}

		for _, c := range v.ExternalChainInfos {
			if c.ChainReferenceID != "eth-main" {
				continue
			}

			cs.Validators = append(cs.Validators, ethcommon.HexToAddress(c.Address))
			break
		}
		power := cMaxPower * (float64(v.ShareCount) / float64(totalPower))
		cs.Powers = append(cs.Powers, big.NewInt(int64(power)))
	}

	cs.ValsetId = big.NewInt(int64(val.Snapshot.Id))

	if len(cs.Validators) != len(cs.Powers) {
		panic("validator power mismatch")
	}
	return cs
}

func printVersion() bool {
	if len(os.Args) < 2 || os.Args[1] != "version" {
		return false
	}

	fmt.Printf("Relay\nVersion: %s\nCommit: %s\n", config.Version(), config.Commit())
	return true
}

func parseArgs() (uint64, string, string, error) {
	if len(os.Args) != 4 {
		return 0, "", "", fmt.Errorf("expected exactly 3 argument [msgId] [path-to-pigeon-config] [eth-rpc-url]")
	}

	id, err := strconv.ParseUint(os.Args[1], 10, 64)
	return id, os.Args[2], os.Args[3], err
}

func callSmartContract(
	method string,
	args []any,
	abi abi.ABI,
	client *ethclient.Client,
	sender ethcommon.Address,
	contract ethcommon.Address,
	keystore *keystore.KeyStore,
) (*ethtypes.Transaction, error) {
	packedBytes, err := abi.Pack(
		method,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack ABI: %w", err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), sender)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %w", err)
	}

	// adapt for eth-main
	gasAdj := big.NewFloat(2)
	gasAdj = gasAdj.Mul(gasAdj, new(big.Float).SetInt(gasPrice))
	gasPrice, _ = gasAdj.Int(big.NewInt(0))

	var gasTipCap *big.Int

	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(2)) // double gas price for EIP-1559 tx
	gasTipCap, err = client.SuggestGasTipCap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas tip cap: %w", err)
	}
	gasPrice = gasPrice.Add(gasPrice, gasTipCap)

	boundContract := bind.NewBoundContract(
		contract,
		abi,
		client,
		client,
		client,
	)

	txOpts, err := bind.NewKeyStoreTransactorWithChainID(
		keystore,
		accounts.Account{Address: sender},
		big.NewInt(1),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to setup keystore transactor: %w", err)
	}

	txOpts.Nonce = big.NewInt(int64(nonce))
	txOpts.From = sender

	value := new(big.Int)
	gasFeeCap := new(big.Int)
	var gasLimit uint64
	gasFeeCap = gasPrice
	gasLimit, err = estimateGasLimit(context.Background(), client, txOpts, &contract, packedBytes, nil, gasTipCap, gasFeeCap, value)
	if err != nil {
		return nil, fmt.Errorf("failed to estimate gas limit: %w", err)
	}
	txOpts.GasLimit = uint64(float64(gasLimit) * 1.2)
	txOpts.GasFeeCap = gasPrice
	txOpts.GasTipCap = gasTipCap
	txOpts.GasPrice = nil

	tx, err := boundContract.RawTransact(txOpts, packedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to raw transact: %w", err)
	}

	return tx, nil
}

func loadABI() (abi.ABI, error) {
	fi, err := os.Open("./data/abi.json")
	if err != nil {
		return abi.ABI{}, fmt.Errorf("failed to open ABI: %v", err)
	}
	aabi, err := abi.JSON(fi)
	if err != nil {
		return abi.ABI{}, fmt.Errorf("failed to parse ABI: %v", err)
	}

	return aabi, err
}

func estimateGasLimit(ctx context.Context, c *ethclient.Client, opts *bind.TransactOpts, contract *ethcommon.Address, input []byte, gasPrice, gasTipCap, gasFeeCap, value *big.Int) (uint64, error) {
	if contract != nil {
		// Gas estimation cannot succeed without code for method invocations.
		if code, err := c.PendingCodeAt(ctx, *contract); err != nil {
			return 0, err
		} else if len(code) == 0 {
			return 0, bind.ErrNoCode
		}
	}

	msg := ethereum.CallMsg{
		From:      opts.From,
		To:        contract,
		GasPrice:  gasPrice,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Value:     value,
		Data:      input,
	}

	return c.EstimateGas(ctx, msg)
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
		panic(fmt.Sprintf("failed to unlock account with keystore: %v", err))
	}

	return s
}

func (s Signer) sign(bytes []byte) ([]byte, error) {
	return s.keystore.SignHash(
		accounts.Account{Address: s.addr},
		bytes,
	)
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
