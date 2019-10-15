package rsa

import (
	"crypto/rand"
	"math/big"
)

const DefaultE = 65537 // default exponent e of public key

type Cipher struct {
	n, e, d *big.Int
}

func NewCipher(n, e, d big.Int) *Cipher {
	return &Cipher{&n, &e, &d}
}

func GenerateRandCipher(bits int) (*Cipher, error) {
	var err error
	p, q, ok := &big.Int{}, &big.Int{}, 0
	primeCheck := big.NewInt(DefaultE + 1)
	for ok == 0 {
		p, err = rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		q, err = rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		// check whether p-1 or q-1 is equal to e
		ok = primeCheck.CmpAbs(p) * primeCheck.CmpAbs(q)
	}

	n := new(big.Int).Mul(p, q)
	f := new(big.Int).Mul(new(big.Int).Add(p, big.NewInt(-1)), new(big.Int).Add(q, big.NewInt(-1))) // φ(n)
	e := big.NewInt(DefaultE)
	d := new(big.Int).ModInverse(e, f) // Extended GCD
	return &Cipher{n, e, d}, nil
}

func (c *Cipher) ExportKey() (big.Int, big.Int, big.Int) {
	return *c.n, *c.e, *c.d
}

func (c *Cipher) Encrypt(src []byte) (dst []byte) {
	M := new(big.Int).SetBytes(src)
	C := new(big.Int).Exp(M, c.e, c.n) // Fast Exponentiation
	return C.Bytes()
}

func (c *Cipher) Decrypt(src []byte) (dst []byte) {
	C := new(big.Int).SetBytes(src)
	M := new(big.Int).Exp(C, c.d, c.n) // Fast Exponentiation
	return M.Bytes()
}
