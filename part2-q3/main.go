package main

import (
	"encoding/binary"
	"fmt"
)

// Generate subkeys using a simple circular shift
func generateSubkeys(key uint64, rounds int) []uint32 {
	subkeys := make([]uint32, rounds)
	for i := 0; i < rounds; i++ {
		subkey := (key << i) | (key >> (64 - i))
		subkeys[i] = uint32(subkey & 0xFFFFFFFF)
	}
	return subkeys
}

// Feistel round function
func F(R uint32, K uint32) uint32 {
	R_rotated := (R << 4) | (R >> (32 - 4))
	return R_rotated ^ K
}

// Split a 64-bit block into two 32-bit halves
func splitBlock(block uint64) (uint32, uint32) {
	L := uint32((block >> 32) & 0xFFFFFFFF)
	R := uint32(block & 0xFFFFFFFF)
	return L, R
}

// Join two 32-bit halves into a 64-bit block
func joinBlock(L uint32, R uint32) uint64 {
	return (uint64(L) << 32) | uint64(R)
}

// Main Feistel encryption function
func feistelEncrypt(plainText []uint64, key uint64) []uint64 {
	const rounds = 16

	subkeys := generateSubkeys(key, rounds)
	encryptedBlocks := make([]uint64, len(plainText))

	for i, block := range plainText {
		L, R := splitBlock(block)
		for j := 0; j < rounds; j++ {
			L, R = R, L^F(R, subkeys[j])
		}
		encryptedBlocks[i] = joinBlock(L, R)
	}

	return encryptedBlocks
}

// Convert text to 64-bit blocks
func textToBlocks(text string) []uint64 {
	bytes := []byte(text)
	padding := 8 - (len(bytes) % 8)
	for i := 0; i < padding; i++ {
		bytes = append(bytes, byte(padding))
	}

	blocks := make([]uint64, len(bytes)/8)
	for i := 0; i < len(blocks); i++ {
		blocks[i] = binary.BigEndian.Uint64(bytes[i*8 : (i+1)*8])
	}

	return blocks
}

// Convert 64-bit blocks to text
func blocksToText(blocks []uint64) string {
	bytes := make([]byte, len(blocks)*8)
	for i, block := range blocks {
		binary.BigEndian.PutUint64(bytes[i*8:(i+1)*8], block)
	}

	padding := bytes[len(bytes)-1]
	return string(bytes[:len(bytes)-int(padding)])
}

func main() {
	plainText := "Two hundred sayings are not as good as one deed."
	key := uint64(0x0F1571C947D9E859) // 64-bit key

	plainTextBlocks := textToBlocks(plainText)
	encryptedBlocks := feistelEncrypt(plainTextBlocks, key)

	fmt.Println("Plain text:", plainText)
	fmt.Printf("Encrypted text: %x\n", encryptedBlocks)

	// Decrypt the text for testing
	decryptedBlocks := feistelEncrypt(encryptedBlocks, key)
	decryptedText := blocksToText(decryptedBlocks)
	fmt.Println("Decrypted text:", decryptedText)
}
