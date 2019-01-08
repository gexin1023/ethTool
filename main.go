package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Println("========== ethTool ==========")

	if len(os.Args) < 2 {
		help()
		return
	}

	arg := os.Args[1]
	params := os.Args[2:]

	parseArg(arg, params)
}
func help() {
	fmt.Println("ethTool arg [params]")
	fmt.Println("arg:")
	fmt.Println("\t help")
	fmt.Println("\t genKey")
	fmt.Println("\t prvToPub\t privateKey")
	fmt.Println("\t hash\t\t msg")
	fmt.Println("\t sign\t\t msg privateKey")
	fmt.Println("\t verify\t\t msg signature  address")
}

func parseArg(arg string, params []string) {
	if arg == "help" {
		help()
	} else if arg == "genKey" {
		genKey()
	} else if arg == "prvToPub" {
		if len(params) < 1 {
			fmt.Println("prvkey need input")
			return
		}
		prvToPub(params[0])
	} else if arg == "hash" {
		if len(params) < 1 {
			fmt.Println("hash need input")
			return
		}
		sha3Hash(params[0])
	} else if arg == "sign" {
		if len(params) != 2 {
			fmt.Println("sign need 2 string params")
			return
		}
		sign(params[0], params[1])
	} else if arg == "verify" {
		if len(params) != 3 {
			fmt.Println("verify need 3 string params")
			return
		}
		verify(params[0], params[1], params[2])
	} else {
		help()
	}
}

func sha3Hash(msg string) string {
	fmt.Println("========== sha3-hash ==========")

	ret := hex.EncodeToString(crypto.Keccak256([]byte(msg)))
	fmt.Println("hash of ", msg, ": ", ret)
	return ret
}

func genKey() (prv, pub, addr string) {
	fmt.Println("========== generate Key ==========")

	prvKey, err := crypto.GenerateKey()
	if err != nil {
		return "", "", ""
	}

	prv = hex.EncodeToString(crypto.FromECDSA(prvKey))

	pub = hex.EncodeToString(crypto.FromECDSAPub(&prvKey.PublicKey))

	addrT := crypto.PubkeyToAddress(prvKey.PublicKey)
	addr = addrT.String()

	fmt.Println("privateKey: ", prv)
	fmt.Println("publicKey: ", pub)
	fmt.Println("address: ", addr)

	return prv, pub, addr
}

func prvToPub(prv string) {
	if prv[:2] == "0x" {
		prv = prv[2:]
	}

	prvBytes, err := hex.DecodeString(prv)
	if err != nil {
		fmt.Println("decode private key string error")
		return
	}

	prvK, err := crypto.ToECDSA(prvBytes)
	if err != nil {
		fmt.Println("bytes to private key error")
		return
	}

	prvStr := hex.EncodeToString(crypto.FromECDSA(prvK))
	pubStr := hex.EncodeToString(crypto.FromECDSAPub(&prvK.PublicKey))
	addr := crypto.PubkeyToAddress(prvK.PublicKey)

	fmt.Println("privateKey: ", prvStr)
	fmt.Println("publicKey: ", pubStr)
	fmt.Println("address: ", addr.String())
}

func sign(msg, prv string) (sig string) {
	fmt.Println("========== sign ==========")

	if prv[0:2] == "0x" {
		prv = prv[2:]
	}

	prvK, _ := crypto.HexToECDSA(prv)

	h := crypto.Keccak256([]byte(msg))

	fmt.Println("the hash of msg: ", hex.EncodeToString(h))

	sigBytes, _ := crypto.Sign(h, prvK)

	sig = hex.EncodeToString(sigBytes)

	fmt.Println("signature: ", sig)

	return sig
}

func verify(msg, sig, addr string) (ret string) {
	fmt.Println("========== verify ==========")

	hashBytes := crypto.Keccak256([]byte(msg))

	if sig[0:2] == "0x" {
		sig = sig[2:]
	}

	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		fmt.Println("signature cannot be paresed")
		return "false"
	}

	pubK, err := crypto.SigToPub(hashBytes, sigBytes)

	addrT := crypto.PubkeyToAddress(*pubK)

	addrIn := common.HexToAddress(addr)

	if addrT.String() != addrIn.String() {

		fmt.Println("verify failed")
		fmt.Println("get address from signature: ", addrT.String())
		return "false"
	}
	fmt.Println("verify success ^_^")
	return "true"
}
