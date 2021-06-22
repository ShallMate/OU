package OU

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var ErrMessageTooLong = errors.New("OU: message too long for OU public key size")

func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// First, begin generation of p in the background.
	var p *big.Int
	var errChan = make(chan error, 1)
	go func() {
		var err error
		p, err = rand.Prime(random, bits/3)
		errChan <- err
	}()

	// Now, find a prime q in the foreground.
	q, err := rand.Prime(random, bits/3)
	if err != nil {
		return nil, err
	}
	//fmt.Println(p.BitLen())
	//fmt.Println(q.BitLen())

	// Wait for generation of p to complete successfully.
	if err := <-errChan; err != nil {
		return nil, err
	}
	pminusone := new(big.Int).Sub(p, one)
	/*
		x := big.NewInt(1)
		y := big.NewInt(1)
		pminusone := new(big.Int).Sub(p, one)
		qminusone := new(big.Int).Sub(q, one)
		p_1q := new(big.Int).GCD(x, y, pminusone, q)
		fmt.Println(p_1q)
		pq_1 := new(big.Int).GCD(x, y, qminusone, p)
		fmt.Println(pq_1)
	*/
	pp := new(big.Int).Mul(p, p)
	// n = p^2*q
	n := new(big.Int).Mul(pp, q)
	//fmt.Println(n.BitLen())
	// g->[0,n-1)
	g, _ := rand.Int(random, n)
	//p-1

	//gp = g^p-1 mod p^2
	gp := new(big.Int).Exp(g, pminusone, pp)
	lgp := l(gp, p)
	invlgp := new(big.Int).ModInverse(lgp, p)
	//h = g^n mod n
	h := new(big.Int).Exp(g, n, n)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			PSquared: pp,
			G:        g,
			H:        h,
			Gp:       gp,
			InvLGp:   invlgp,
		},
		p:         p,
		q:         q,
		pminusone: pminusone,
	}, nil

}

type PrivateKey struct {
	PublicKey
	p         *big.Int
	pminusone *big.Int
	q         *big.Int
}

type PublicKey struct {
	N        *big.Int // modulus
	G        *big.Int // n+1, since p and q are same length
	Gp       *big.Int
	H        *big.Int
	PSquared *big.Int
	InvLGp   *big.Int
}

func Encrypt(pubKey *PublicKey, plainText []byte) (*big.Int, error) {
	m := new(big.Int).SetBytes(plainText)
	n := pubKey.N
	h := pubKey.H
	g := pubKey.G
	r, _ := rand.Int(rand.Reader, n)
	// c = g^m * h^r mod n
	c1 := new(big.Int).Exp(g, m, n)
	c2 := new(big.Int).Exp(h, r, n)
	c := new(big.Int).Mul(c1, c2)
	c = c.Mod(c, n)
	return c, nil
}

// L(x) = x-1/p
func l(x *big.Int, p *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), p)
}

func Decrypt(privKey *PrivateKey, c *big.Int) (*big.Int, error) {

	//cp=c^p-1 mod p^2
	cp := new(big.Int).Exp(c, privKey.pminusone, privKey.PSquared)
	//L(cp) = cp-1/p
	lcp := l(cp, privKey.p)

	m := new(big.Int).Mul(lcp, privKey.InvLGp)
	m = m.Mod(m, privKey.p)
	return m, nil
}

func AddCipher(c1 *big.Int, c2 *big.Int, pubKey *PublicKey) *big.Int {
	c := new(big.Int).Mul(c1, c2)
	c = c.Mod(c, pubKey.N)
	return c
}

func MulCipher(c1 *big.Int, p *big.Int, pubKey *PublicKey) *big.Int {
	c := new(big.Int).Exp(c1, p, pubKey.N)
	return c
}

/*
func h(p *big.Int, pp *big.Int, n *big.Int) *big.Int {
	gp := new(big.Int).Mod(new(big.Int).Sub(one, n), pp)
	lp := l(gp, p)
	hp := new(big.Int).ModInverse(lp, p)
	return hp
}

func l(u *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(u, one), n)
}

// Encrypt encrypts a plain text represented as a byte array. The passed plain
// text MUST NOT be larger than the modulus of the passed public key.
func Encrypt(pubKey *PublicKey, plainText []byte) ([]byte, error) {
	c, _, err := EncryptAndNonce(pubKey, plainText)
	return c, err
}

// EncryptAndNonce encrypts a plain text represented as a byte array, and in
// addition, returns the nonce used during encryption. The passed plain text
// MUST NOT be larger than the modulus of the passed public key.
func EncryptAndNonce(pubKey *PublicKey, plainText []byte) ([]byte, *big.Int, error) {
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, nil, err
	}

	c, err := EncryptWithNonce(pubKey, r, plainText)
	if err != nil {
		return nil, nil, err
	}

	return c.Bytes(), r, nil
}

// EncryptWithNonce encrypts a plain text represented as a byte array using the
// provided nonce to perform encryption. The passed plain text MUST NOT be
// larger than the modulus of the passed public key.
func EncryptWithNonce(pubKey *PublicKey, r *big.Int, plainText []byte) (*big.Int, error) {
	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 { // N < m
		return nil, ErrMessageTooLong
	}

	// c = g^m * r^n mod n^2 = ((m*n+1) mod n^2) * r^n mod n^2
	n := pubKey.N
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(one, new(big.Int).Mul(m, n)), pubKey.NSquared),
			new(big.Int).Exp(r, n, pubKey.NSquared),
		),
		pubKey.NSquared,
	)

	return c, nil
}

// Decrypt decrypts the passed cipher text.
func Decrypt(privKey *PrivateKey, cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if privKey.NSquared.Cmp(c) < 1 { // c < n^2
		return nil, ErrMessageTooLong
	}

	cp := new(big.Int).Exp(c, privKey.pminusone, privKey.pp)
	lp := l(cp, privKey.p)
	mp := new(big.Int).Mod(new(big.Int).Mul(lp, privKey.hp), privKey.p)
	cq := new(big.Int).Exp(c, privKey.qminusone, privKey.qq)
	lq := l(cq, privKey.q)

	mqq := new(big.Int).Mul(lq, privKey.hq)
	mq := new(big.Int).Mod(mqq, privKey.q)
	m := crt(mp, mq, privKey)

	return m.Bytes(), nil
}

func crt(mp *big.Int, mq *big.Int, privKey *PrivateKey) *big.Int {
	u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(mq, mp), privKey.pinvq), privKey.q)
	m := new(big.Int).Add(mp, new(big.Int).Mul(u, privKey.p))
	return new(big.Int).Mod(m, privKey.n)
}

// AddCipher homomorphically adds together two cipher texts.
// To do this we multiply the two cipher texts, upon decryption, the resulting
// plain text will be the sum of the corresponding plain texts.
func AddCipher(pubKey *PublicKey, cipher1, cipher2 []byte) []byte {
	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)

	// x * y mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pubKey.NSquared,
	).Bytes()
}

func MulCipher(pubKey *PublicKey, cipher1 []byte, p *big.Int) []byte {
	x := new(big.Int).SetBytes(cipher1)
	//y := new(big.Int).SetBytes(cipher2)
	return new(big.Int).Exp(x, p, pubKey.NSquared).Bytes()
}

// Add homomorphically adds a passed constant to the encrypted integer
// (our cipher text). We do this by multiplying the constant with our
// ciphertext. Upon decryption, the resulting plain text will be the sum of
// the plaintext integer and the constant.
func Add(pubKey *PublicKey, cipher, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c * g ^ x mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(c, new(big.Int).Exp(pubKey.G, x, pubKey.NSquared)),
		pubKey.NSquared,
	).Bytes()
}

// Mul homomorphically multiplies an encrypted integer (cipher text) by a
// constant. We do this by raising our cipher text to the power of the passed
// constant. Upon decryption, the resulting plain text will be the product of
// the plaintext integer and the constant.
func Mul(pubKey *PublicKey, cipher []byte, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c ^ x mod n^2
	return new(big.Int).Exp(c, x, pubKey.NSquared).Bytes()
}
*/
