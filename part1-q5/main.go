package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func EncryptAES(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func DecryptAES(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

func main() {
	key := []byte("examplekey123456")
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		fmt.Println("Error: AES key must be either 16, 24, or 32 bytes long.")
		return
	}

	plaintext := []byte("Helloooo,itsMeee")
	ciphertext, err := EncryptAES(key, plaintext)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	decrypted, err := DecryptAES(key, ciphertext)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}
	fmt.Printf("Decrypted: %s\n", decrypted)
}
