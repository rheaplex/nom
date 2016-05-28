// nom
// Create names
// Copyright 2016 Rhea Myers <rhea@myers.studio>
// License: GNU GPLv3 or, at your option, any later version.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"encoding/hex"
	"github.com/bren2010/proquint"
	"github.com/tv42/base58"
	"github.com/tyler-smith/go-bip39"
	"hash"
	"math/big"
	"io/ioutil"
	"os"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func readEntropy() []byte {
	// 256 bits
	b := make([]byte, 32)
	_, err := rand.Read(b)
	check(err)
	return b
}

// Allow the user to specify different hash representations

func hashString(hasher hash.Hash, hashRep string) string {
	str := ""
	if hashRep == "base58" {
		bigNum := new(big.Int)
		bigNum.SetBytes(hasher.Sum(nil)[:])
		rep := base58.EncodeBig(nil, bigNum)
		str = string(rep)
	} else if hashRep == "bip39" {
		str, _ = bip39.NewMnemonic(hasher.Sum(nil)[:])
	} else if hashRep == "proquint" {
        str = proquint.Encode(hasher.Sum(nil)[:])
    } else {
		// Convert [32]byte to []byte
		str = hex.EncodeToString(hasher.Sum(nil)[:])
	}
	return str
}

func main() {
	flag.CommandLine.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nom [OPTIONS]")
		fmt.Fprintln(os.Stderr, "       Defaults to using 32 bytes of entropy.")
		flag.PrintDefaults()
	}

	hashRep := flag.String("rep", "hex",
		"hash representation - hex, base58, bip39 or proquint")

	readFromStdin := flag.Bool("stdin", false,
		"read the bytes to hash from stdin rather than as an argument")

	seed := flag.String("seed", "",
		"read the bytes to hash as the parameter of this argument")
	
	flag.Parse()

	var source []byte

	if *readFromStdin {
		if *seed != "" {
			flag.Usage();
			os.Exit(1);
		}
		var err error
		source, err = ioutil.ReadAll(os.Stdin)
		check(err)
	} else if *seed != "" {
		source = []byte(*seed)
	} else {
		source = readEntropy()
	}

	// Hash & print
	hasher := sha256.New()
	hasher.Write(source)
	hashed := hashString(hasher, *hashRep)
	fmt.Println(hashed)
}
