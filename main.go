package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/consensushashing"
	"github.com/kaspanet/kaspad/domain/consensus/utils/constants"
	"github.com/kaspanet/kaspad/domain/consensus/utils/subnetworks"
	"github.com/kaspanet/kaspad/domain/consensus/utils/transactionid"
	"github.com/kaspanet/kaspad/domain/consensus/utils/txscript"
	utxopkg "github.com/kaspanet/kaspad/domain/consensus/utils/utxo"
	"github.com/kaspanet/kaspad/domain/dagconfig"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/kaspanet/kaspad/util/profiling"

	"encoding/hex"

	"github.com/kaspanet/go-secp256k1"
	"github.com/kaspanet/kaspad/infrastructure/os/signal"
	"github.com/kaspanet/kaspad/util"
	"github.com/kaspanet/kaspad/util/panics"

	"github.com/pkg/errors"
)

var shutdown int32 = 0

func main() {

	prefix := dagconfig.DevnetParams.Prefix

	// Insert here the result of genkeypair operation
	myPrivateKey := "74dec232e258cb7aa481c6ace3de06dedca588a15c7434f7ed75d830ce2cc5eb"
	myAddressString := "kaspadev:qz9kd82dp2qd52vm97t94upugr74deg38yrqccxcncj5nwj2sqh0stv9w5sph"
	recipientAddressString := "kaspadev:qrd9frpfnry9p67m88ste9wegcdlnakyvsr8ze2l5sgjhcv5lz3zvgev7p2ww"

	// Some Private / Public keys manipulation
	myAddress, err := util.DecodeAddress(myAddressString, prefix)
	if err != nil {
		panic(err)
	}

	recipientAddress, err := util.DecodeAddress(recipientAddressString, prefix)
	if err != nil {
		panic(err)
	}

	myKeyPair, myPublicKey, err := parsePrivateKeyInKeyPair(myPrivateKey)
	if err != nil {
		panic(err)
	}

	pubKeySerialized, err := myPublicKey.Serialize()
	if err != nil {
		panic(err)
	}

	pubKeyAddr, err := util.NewAddressPublicKey(pubKeySerialized[:], prefix)
	if err != nil {
		panic(err)
	}

	fmt.Println("myPrivateKey: ", myPrivateKey)
	fmt.Println("myKeyPair: ", myKeyPair)
	fmt.Println()
	fmt.Println("myPublicKey: ", myPublicKey)
	fmt.Println("pubKeySerialized: ", pubKeySerialized)
	fmt.Println()
	fmt.Println("myAddress: ", myAddress)
	fmt.Println("pubKeyAddr: ", pubKeyAddr)
	fmt.Println()
	fmt.Println("recipientAddress: ", recipientAddress)
	fmt.Println()

	// Redeem recipient private key and address
	redeemPrivateKey := "09c97007242fb2078c6f78e991f7d43fdcd94ccd21655f54dca87a8d777e3a89"
	redeemAddress := recipientAddress
	redeemAddressString := recipientAddressString
	redeemKeyPair, redeemPublicKey, err := parsePrivateKeyInKeyPair(redeemPrivateKey)
	if err != nil {
		panic(err)
	}
	redeemPubKeySerialized, err := redeemPublicKey.Serialize()
	if err != nil {
		panic(err)
	}

	fmt.Println("redeemPrivateKey: ", redeemPrivateKey)
	fmt.Println("redeemKeyPair: ", redeemKeyPair)
	fmt.Println()
	fmt.Println("redeemPublicKey: ", redeemPublicKey)
	fmt.Println("redeemPubKeySerialized: ", redeemPubKeySerialized)
	fmt.Println()
	fmt.Println("redeemAddress: ", redeemAddress)
	fmt.Println()

	interrupt := signal.InterruptListener()
	configError := parseConfig()
	if configError != nil {
		fmt.Fprintf(os.Stderr, "Error parsing config: %+v", err)
		os.Exit(1)
	}
	defer backendLog.Close()

	defer panics.HandlePanic(log, "main", nil)

	if cfg.Profile != "" {
		profiling.Start(cfg.Profile, log)
	}

	// RPC connection setup
	rpcAddress, err := activeConfig().ActiveNetParams.NormalizeRPCServerAddress(activeConfig().RPCServer)
	if err != nil {
		log.Error("RPC address can't be identified:")
		panic(err)
	}

	//RPC client activation (to communicate with Kaspad)
	client, err := rpcclient.NewRPCClient(rpcAddress)
	if err != nil {
		log.Error("RPC client connection can't be activated:")
		panic(err)
	}

	client.SetTimeout(5 * time.Minute)

	// Deploy P2SH contract
	contractP2SHaddress, transactionID, secret, secretContract := initiateContract(client, myKeyPair, myAddress, myAddressString, recipientAddress, prefix)

	// Waiting for the network to deploy the contract (block mined, transaction confirmed)
	fmt.Println("Waiting for network to deploy the contract....")
	fmt.Println()
	time.Sleep(20 * time.Second)

	// Redeem from P2SH contract
	redeemContract(client, contractP2SHaddress.String(), transactionID, redeemKeyPair, redeemPubKeySerialized, redeemAddress, redeemAddressString, prefix, secret, secretContract)

	// The End
	<-interrupt
	atomic.AddInt32(&shutdown, 1)
}

func parsePrivateKeyInKeyPair(privateKeyHex string) (*secp256k1.SchnorrKeyPair, *secp256k1.SchnorrPublicKey, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error parsing private key hex")
	}
	privateKey, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(privateKeyBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error deserializing private key")
	}
	publicKey, err := privateKey.SchnorrPublicKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error generating public key")
	}
	return privateKey, publicKey, nil
}

// Collect spendable UTXOs from address
func fetchAvailableUTXOs(client *rpcclient.RPCClient, address string) (map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, error) {
	getUTXOsByAddressesResponse, err := client.GetUTXOsByAddresses([]string{address})
	if err != nil {
		return nil, err
	}
	dagInfo, err := client.GetBlockDAGInfo()
	if err != nil {
		return nil, err
	}

	spendableUTXOs := make(map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, 0)
	for _, entry := range getUTXOsByAddressesResponse.Entries {
		if !isUTXOSpendable(entry, dagInfo.VirtualDAAScore) {
			continue
		}
		spendableUTXOs[*entry.Outpoint] = entry.UTXOEntry
	}
	return spendableUTXOs, nil
}

// Verify UTXO is spendable (check if a minimum of 10 confirmations have been processed since UTXO creation)
func isUTXOSpendable(entry *appmessage.UTXOsByAddressesEntry, virtualSelectedParentBlueScore uint64) bool {
	blockDAAScore := entry.UTXOEntry.BlockDAAScore
	if !entry.UTXOEntry.IsCoinbase {
		const minConfirmations = 10
		return blockDAAScore+minConfirmations < virtualSelectedParentBlueScore
	}
	coinbaseMaturity := activeConfig().ActiveNetParams.BlockCoinbaseMaturity
	return blockDAAScore+coinbaseMaturity < virtualSelectedParentBlueScore
}

func selectUTXOs(utxos map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, amountToSend uint64) (
	selectedUTXOs []*appmessage.UTXOsByAddressesEntry, selectedValue uint64, err error) {

	selectedUTXOs = []*appmessage.UTXOsByAddressesEntry{}
	selectedValue = uint64(0)

	for outpoint, utxo := range utxos {
		outpointCopy := outpoint
		selectedUTXOs = append(selectedUTXOs, &appmessage.UTXOsByAddressesEntry{
			Outpoint:  &outpointCopy,
			UTXOEntry: utxo,
		})
		selectedValue += utxo.Amount

		if selectedValue >= amountToSend {
			break
		}

		const maxInputs = 100
		if len(selectedUTXOs) == maxInputs {
			log.Infof("Selected %d UTXOs so sending the transaction with %d sompis instead "+
				"of %d", maxInputs, selectedValue, amountToSend)
			break
		}
	}

	return selectedUTXOs, selectedValue, nil
}

// Generate transaction data for initiating contract
func initiateContractTransaction(keyPair *secp256k1.SchnorrKeyPair, P2SH []byte, selectedUTXOs []*appmessage.UTXOsByAddressesEntry,
	sompisToSend uint64, change uint64, fromAddress util.Address) (*appmessage.RPCTransaction, error) {

	// Generate transaction input from selectedUTXOs, collected from address query to Kaspad
	inputs := make([]*externalapi.DomainTransactionInput, len(selectedUTXOs))
	for i, utxo := range selectedUTXOs {
		outpointTransactionIDBytes, err := hex.DecodeString(utxo.Outpoint.TransactionID)
		if err != nil {
			return nil, err
		}
		outpointTransactionID, err := transactionid.FromBytes(outpointTransactionIDBytes)
		if err != nil {
			return nil, err
		}
		outpoint := externalapi.DomainOutpoint{
			TransactionID: *outpointTransactionID,
			Index:         utxo.Outpoint.Index,
		}
		utxoScriptPublicKeyScript, err := hex.DecodeString(utxo.UTXOEntry.ScriptPublicKey.Script)
		if err != nil {
			return nil, err
		}

		inputs[i] = &externalapi.DomainTransactionInput{
			PreviousOutpoint: outpoint,
			SigOpCount:       1,
			UTXOEntry: utxopkg.NewUTXOEntry(
				utxo.UTXOEntry.Amount,
				&externalapi.ScriptPublicKey{
					Script:  utxoScriptPublicKeyScript,
					Version: utxo.UTXOEntry.ScriptPublicKey.Version,
				},
				utxo.UTXOEntry.IsCoinbase,
				utxo.UTXOEntry.BlockDAAScore,
			),
		}
	}

	// Generate transaction output to pay recipient address
	mainOutput := &externalapi.DomainTransactionOutput{
		Value: sompisToSend,
		ScriptPublicKey: &externalapi.ScriptPublicKey{
			Version: constants.MaxScriptPublicKeyVersion,
			Script:  P2SH,
		},
	}

	// Generate ScriptPublicKey for change address
	fromScript, err := txscript.PayToAddrScript(fromAddress)
	if err != nil {
		return nil, err
	}

	// Generate array of Outputs and add "change address output", in case change have to be sent back to recipient address
	outputs := []*externalapi.DomainTransactionOutput{mainOutput}
	if change > 0 {
		changeOutput := &externalapi.DomainTransactionOutput{
			Value:           change,
			ScriptPublicKey: fromScript,
		}
		outputs = append(outputs, changeOutput)
	}

	// Generate transaction data (not yet signed)
	domainTransaction := &externalapi.DomainTransaction{
		Version:      constants.MaxTransactionVersion,
		Inputs:       inputs,
		Outputs:      outputs,
		LockTime:     0,
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Gas:          0,
		Payload:      nil,
	}

	// Sign all inputs in transaction
	for i, input := range domainTransaction.Inputs {
		signatureScript, err := txscript.SignatureScript(domainTransaction, i, consensushashing.SigHashAll, keyPair,
			&consensushashing.SighashReusedValues{})
		if err != nil {
			return nil, err
		}
		input.SignatureScript = signatureScript
	}

	// Convert transaction into a RPC transaction, ready to be broadcasted
	rpcTransaction := appmessage.DomainTransactionToRPCTransaction(domainTransaction)
	return rpcTransaction, nil
}

// Generate transaction data for redeeming contract
func redeemContractTransaction(contractTransactionID string, selectedUTXOToRedeem []*appmessage.UTXOsByAddressesEntry, redeemKeyPair *secp256k1.SchnorrKeyPair, redeemPubKeySerialized *secp256k1.SerializedSchnorrPublicKey, secret []byte, secretContract []byte, recipientAddress util.Address) (*appmessage.RPCTransaction, error) {

	inputs := make([]*externalapi.DomainTransactionInput, len(selectedUTXOToRedeem))
	for i, utxo := range selectedUTXOToRedeem {
		outpointTransactionIDBytes, err := hex.DecodeString(utxo.Outpoint.TransactionID)
		if err != nil {
			return nil, err
		}
		outpointTransactionID, err := transactionid.FromBytes(outpointTransactionIDBytes)
		if err != nil {
			return nil, err
		}
		outpoint := externalapi.DomainOutpoint{
			TransactionID: *outpointTransactionID,
			Index:         utxo.Outpoint.Index,
		}
		utxoScriptPublicKeyScript, err := hex.DecodeString(utxo.UTXOEntry.ScriptPublicKey.Script)
		if err != nil {
			return nil, err
		}

		inputs[i] = &externalapi.DomainTransactionInput{
			PreviousOutpoint: outpoint,
			SigOpCount:       0,
			UTXOEntry: utxopkg.NewUTXOEntry(
				utxo.UTXOEntry.Amount,
				&externalapi.ScriptPublicKey{
					Script:  utxoScriptPublicKeyScript,
					Version: utxo.UTXOEntry.ScriptPublicKey.Version,
				},
				utxo.UTXOEntry.IsCoinbase,
				utxo.UTXOEntry.BlockDAAScore,
			),
		}
	}

	valueToRedeem := selectedUTXOToRedeem[0].UTXOEntry.Amount

	var feePerInput = uint64(30000)
	scriptPubkey, _ := txscript.PayToAddrScript(recipientAddress)
	outputs := []*externalapi.DomainTransactionOutput{{
		Value:           (valueToRedeem - uint64(feePerInput)*uint64(len(inputs))),
		ScriptPublicKey: scriptPubkey,
	}}

	// Generate transaction data (not yet signed)
	domainTransaction := &externalapi.DomainTransaction{
		Version:      constants.MaxTransactionVersion,
		Inputs:       inputs,
		Outputs:      outputs,
		LockTime:     0,
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Gas:          0,
		Payload:      nil,
	}

	// Sign all inputs in transaction
	for i, input := range domainTransaction.Inputs {
		signatureScript, err := txscript.SignatureScript(domainTransaction, i, consensushashing.SigHashAll, redeemKeyPair, &consensushashing.SighashReusedValues{})
		if err != nil {
			return nil, err
		}

		redeemScript, err := redeemP2SHContract(signatureScript, secretContract, []byte(redeemPubKeySerialized.String()), secret)
		if err != nil {
			log.Error("Cannot create Redeem Script: ")
			panic(err)
		}

		plainRedeemScript, err := txscript.DisasmString(0, redeemScript)
		if err != nil {
			log.Error("Script contract can't be correctly created:")
			panic(err)
		}
		fmt.Println("plainRedeemScript: ")
		fmt.Println(plainRedeemScript)
		fmt.Println()

		input.SignatureScript = redeemScript
	}

	// Convert transaction into a RPC transaction, ready to be broadcasted
	rpcTransaction := appmessage.DomainTransactionToRPCTransaction(domainTransaction)
	return rpcTransaction, nil
}

// Broadcast transaction on the network
func sendTransaction(client *rpcclient.RPCClient, rpcTransaction *appmessage.RPCTransaction) (string, error) {
	submitTransactionResponse, err := client.SubmitTransaction(rpcTransaction, false)
	if err != nil {
		return "", errors.Wrapf(err, "error submitting transaction")
	}
	return submitTransactionResponse.TransactionID, nil
}

func secretContract(pubkhThem []byte, secretHash []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()

	// Require initiator's secret to be known to redeem the output.
	b.AddOp(txscript.OpSHA256)
	b.AddData(secretHash)
	b.AddOp(txscript.OpEqual)

	// Verify their signature is being used to redeem the output.  This
	// would normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been
	// moved outside of the branch to save a couple bytes.
	/*
		b.AddOp(txscript.OpDup)
		b.AddOp(txscript.OpBlake2b)
		b.AddData(pubkhThem)
	*/

	// Complete the signature check.
	//b.AddOp(txscript.OpEqualVerify)
	//b.AddOp(txscript.OpCheckSig)

	return b.Script()
}

func initiateContract(client *rpcclient.RPCClient, myKeyPair *secp256k1.SchnorrKeyPair, myAddress util.Address, myAddressString string, recipientAddress util.Address, prefix util.Bech32Prefix) (*util.AddressScriptHash, string, []byte, []byte) {

	//Fetch UTXOs from address
	availableUtxos, err := fetchAvailableUTXOs(client, myAddressString)
	if err != nil {
		log.Error("Available UTXOs can't be fetched:")
		panic(err)
	}

	//Define amount to send
	const balanceEpsilon = 10_000         // 10,000 sompi = 0.0001 kaspa
	const feeAmount = balanceEpsilon * 10 // use high fee amount, because can have a large number of inputs
	const sendAmount = balanceEpsilon * 1000
	totalSendAmount := uint64(sendAmount + feeAmount)

	//Select UTXOs matching Total Send amount
	selectedUTXOs, selectedValue, err := selectUTXOs(availableUtxos, totalSendAmount)
	if err != nil {
		log.Error("UTXOs can't be selected:")
		panic(err)
	}
	if len(selectedUTXOs) == 0 {
		log.Error("No UTXOs has been selected")
	}

	//Define change amount from selected UTXOs
	change := selectedValue - sendAmount - feeAmount

	secretString := "c66531fb402f0088d9f5be954cbfededef83a9d3100ef028d57c5aef2dedba3a"
	secret, _ := hex.DecodeString(secretString)
	secretHash := sha256Hash(secret[:])

	fmt.Println("SECRET: ")
	fmt.Println(hex.EncodeToString(secret[:]))
	fmt.Println("")

	fmt.Println("SECRET HASH:")
	fmt.Println(hex.EncodeToString(secretHash))
	fmt.Println("")

	// Generate locking contract based on secret and recipient pubkey
	secretContract, err := secretContract(recipientAddress.ScriptAddress(), secretHash)
	if err != nil {
		log.Error("Script contract can't be correctly created:")
		panic(err)
	}
	fmt.Println("Contract:")
	fmt.Println(hex.EncodeToString(secretContract))
	fmt.Println("")

	plainSecretContract, err := txscript.DisasmString(0, secretContract)
	if err != nil {
		log.Error("Script contract can't be correctly created:")
		panic(err)
	}
	fmt.Println("PlainSecretContract: ")
	fmt.Println(plainSecretContract)
	fmt.Println()

	// Generate script contract address
	contractP2SHaddress, err := util.NewAddressScriptHash(secretContract, prefix)
	if err != nil {
		log.Error("New address for contract can't be created: ")
		panic(err)
	}
	fmt.Println("contractP2SHaddress:")
	fmt.Println(contractP2SHaddress)
	fmt.Println("")

	// Generate P2HS contract
	contractP2SHPkScript, err := txscript.PayToScriptHashScript(secretContract)
	if err != nil {
		log.Error("P2HS for contract can't be created: ")
		panic(err)
	}
	fmt.Println("ContractP2SHPkScript:")
	fmt.Println(hex.EncodeToString(contractP2SHPkScript))
	fmt.Println("")

	// Create transaction
	rpcTransaction, err := initiateContractTransaction(myKeyPair, contractP2SHPkScript, selectedUTXOs, sendAmount, change, myAddress)
	if err != nil {
		log.Error("RpcTransaction can't be created: ")
		panic(err)
	}

	//Broadcast transaction
	transactionID, err := sendTransaction(client, rpcTransaction)
	if err != nil {
		log.Error("Transaction can't be correctly broadcasted:")
		panic(err)
	} else {
		log.Infof("Transaction has been successfully broadcasted: %s", transactionID)
	}

	return contractP2SHaddress, transactionID, secret, secretContract
}

func redeemContract(client *rpcclient.RPCClient, contractP2SHaddress string, transactionID string, redeemKeyPair *secp256k1.SchnorrKeyPair, redeemPubKeySerialized *secp256k1.SerializedSchnorrPublicKey, redeemAddress util.Address, redeemAddressString string, prefix util.Bech32Prefix, secret []byte, secretContract []byte) {

	fmt.Println("Starting redeem operation...")
	fmt.Println("")

	fmt.Println("Contract to redeem:")
	fmt.Println(hex.EncodeToString(secretContract))
	fmt.Println("")

	plainSecretContract, err := txscript.DisasmString(0, secretContract)
	if err != nil {
		log.Error("Script contract can't be correctly created:")
		panic(err)
	}
	fmt.Println("PlainSecretContract to redeem: ")
	fmt.Println(plainSecretContract)
	fmt.Println()

	//Fetch UTXOs from address
	availableUtxos, err := fetchAvailableUTXOs(client, contractP2SHaddress)
	if err != nil {
		log.Error("Available UTXOs can't be fetched:")
		panic(err)
	}

	//Select UTXOs matching contract TX
	selectedUTXOToRedeem, err := selectUTXOToRedeem(availableUtxos, transactionID)
	if err != nil {
		log.Error("UTXOs can't be selected:")
		panic(err)
	}
	if len(selectedUTXOToRedeem) == 0 {
		log.Error("No UTXOs has been selected")
	}

	// Create transaction
	rpcTransaction, err := redeemContractTransaction(transactionID, selectedUTXOToRedeem, redeemKeyPair, redeemPubKeySerialized, secret, secretContract, redeemAddress)
	if err != nil {
		log.Error("RpcTransaction can't be created: ")
		panic(err)
	}

	//Broadcast transaction
	redeemTransactionID, err := sendTransaction(client, rpcTransaction)
	if err != nil {
		log.Error("Transaction can't be correctly broadcasted:")
		panic(err)
	} else {
		log.Infof("Transaction has been successfully broadcasted: %s", redeemTransactionID)
	}
}

func selectUTXOToRedeem(availableUtxos map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, contractTxID string) (selectedUTXOs []*appmessage.UTXOsByAddressesEntry, err error) {

	selectedUTXOs = []*appmessage.UTXOsByAddressesEntry{}

	for outpoint, utxo := range availableUtxos {
		if outpoint.TransactionID == contractTxID {
			outpointCopy := outpoint
			selectedUTXOs = append(selectedUTXOs, &appmessage.UTXOsByAddressesEntry{
				Outpoint:  &outpointCopy,
				UTXOEntry: utxo,
			})
		}
	}

	return selectedUTXOs, nil
}

func redeemP2SHContract(sig, contract, pubkey, secret []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	//b.AddData(sig)
	//b.AddData(pubkey)
	b.AddData(secret)
	b.AddData(contract)
	return b.Script()
}

func sha256Hash(x []byte) []byte {
	h := sha256.Sum256(x)
	return h[:]
}
