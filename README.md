# 由于在网上没有找到OU同态加密的代码就自己实现了一个

#原论文url

##用法
```
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
  ```
