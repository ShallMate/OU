# 由于在网上没有找到OU同态加密的代码就自己实现了一个

###  [原论文PDF](https://link.springer.com/content/pdf/10.1007/BFb0054135.pdf)

## 用法
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
 
 ## 在n=3072bit下与paillier方案的对比
 
 ### Paillier使用代码[Paillier](https://github.com/Roasbeef/go-go-gadget-paillier)
 
 ```
paillier-3072 1000times encrypto all cost=[39.279695391s]
paillier-3072  1000times decrypto all cost=[10.490600826s]
 ```
 
  ```
OU encrypto 1000 times cost=[9.083451724s]
OU decrypto 1000 times cost=[1.400994954s]
 ```
 
 ### 可以看出OU相较Paillier有相当大的优势
 
 ## 代码有问题可联系:lgwcqupt@qq.com

 
