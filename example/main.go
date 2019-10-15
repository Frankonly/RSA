package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	myrsa "../rsa"
)

var version = "frankonly's RSA v0.1"
var claim = "The length of p and q are both 1024 bits"

func rsaEncrypt(c *myrsa.Cipher, plaintext string) string {
	return "ciphertext:" + hex.EncodeToString(c.Encrypt([]byte(plaintext)))
}
func rsaDecrypt(c *myrsa.Cipher, ciphertext string) string {
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "invalid ciphertext, we need hex ciphertext"
	}
	return "plaintext:" + string(c.Decrypt(cipherBytes))
}

func main() {
	fmt.Printf("%s\n\n%s\n", version, claim)
	var option byte
	run := true
	c, err := myrsa.GenerateRandCipher(1024)
	if err == nil {
		fmt.Println("New cipher has been initialized.")
	} else {
		fmt.Println(err.Error())
	}
	for run {
		fmt.Println("\nOptions:\n(1)Encrypt, (2)Decrypt, (3)Generate Key, (4)Change Key (5)Print Key, (6)Quit")
		_, _ = fmt.Scan(&option)
		switch option {
		default:
			fmt.Println("invalid input")
		case 1:
			fmt.Println("please input plaintext")
			fmt.Println(rsaEncrypt(c, readText()))
		case 2:
			fmt.Println("please input ciphertext")
			fmt.Println(rsaDecrypt(c, readText()))
		case 3:
			c, err = myrsa.GenerateRandCipher(1024)
			if err == nil {
				fmt.Println("New cipher has been initialized.")
			} else {
				fmt.Println(err.Error())
			}
		case 4:
			c = readCipher()
		case 5:
			printKey(c)
		case 6:
			run = false
		}
	}
}

// exponent e is set to the defaultE 65537 here
func readCipher() *myrsa.Cipher {
	n, e, d, ok := big.Int{}, big.Int{}, big.Int{}, false
	for !ok {
		fmt.Print("please input public key n: ")
		_, ok = n.SetString(readText(), 10)
		if !ok {
			fmt.Println("invalid n")
			continue
		}

		fmt.Print("please input public key e: ")
		_, ok = e.SetString(readText(), 10)
		if !ok {
			fmt.Println("invalid e")
			continue
		}

		fmt.Print("please input public key d: ")
		_, ok = d.SetString(readText(), 10)
		if !ok {
			fmt.Println("invalid d")
			continue
		}
	}
	return myrsa.NewCipher(n, *big.NewInt(myrsa.DefaultE), d)
}

func printKey(cipher *myrsa.Cipher) {
	n, c, d := cipher.ExportKey()
	fmt.Printf("n: %s\nc: %s\nd: %s\n", n.String(), c.String(), d.String())
}

func readText() (text string) {
	_, _ = fmt.Scan(&text)
	return
}
