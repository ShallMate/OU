package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	OU "github.com/OU"
)

var OUtimeall time.Duration = 0
var OUenall time.Duration = 0
var OUdeall time.Duration = 0

func TestOUCost() {
	privKey, _ := OU.GenerateKey(rand.Reader, 3072)
	msgmax := big.NewInt(4294967296)
	var messages [1000]*big.Int

	for i := 0; i < 1000; i++ {
		messages[i], _ = rand.Int(rand.Reader, msgmax)
		fmt.Println(messages[i])
	}
	for i := 0; i < 1000; i++ {
		start1 := time.Now()
		c15, _ := OU.Encrypt(&privKey.PublicKey, messages[i].Bytes())
		cost1 := time.Since(start1)
		fmt.Printf("OU encrypto cost=[%s]\n", cost1)
		OUenall = OUenall + cost1
		start2 := time.Now()
		d, _ := OU.Decrypt(privKey, c15)
		cost2 := time.Since(start2)
		fmt.Printf("OU decrypto cost=[%s]\n", cost2)
		OUdeall = OUdeall + cost2
		cost3 := cost1 + cost2
		OUtimeall = OUtimeall + cost3
		fmt.Println("OU Decryption Result : ", d.String())
	}
	fmt.Printf("OU encrypto 1000 times cost=[%s]\n", OUenall)
	fmt.Printf("OU decrypto 1000 times cost=[%s]\n", OUdeall)
	fmt.Printf("OU  1000 times all cost=[%s]\n", OUtimeall)
}

func main() {
	m15 := big.NewInt(15)
	m20 := big.NewInt(20)

	privKey, _ := OU.GenerateKey(rand.Reader, 3072)

	c15, _ := OU.Encrypt(&privKey.PublicKey, m15.Bytes())
	c20, _ := OU.Encrypt(&privKey.PublicKey, m20.Bytes())
	c35 := OU.AddCipher(c15, c20, &privKey.PublicKey)
	m2 := big.NewInt(2)
	c30 := OU.MulCipher(c15, m2, &privKey.PublicKey)
	d35, _ := OU.Decrypt(privKey, c35)
	d30, _ := OU.Decrypt(privKey, c30)
	fmt.Println("OU Decryption 20+15 Result : ", d35.String())
	fmt.Println("OU Decryption 15*2 Result : ", d30.String())
	//TestOUCost()
}
