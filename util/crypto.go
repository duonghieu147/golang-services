package util

import (
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "encoding/base64"
  "io"
)

// GenerateRandomBytes uses to generate a random bytes by given length
func GenerateRandomBytes(length int) ([]byte, error) {
  buffer := make([]byte, length)
  _, err := rand.Read(buffer)
  if err != nil {
    return nil, err
  }
  return buffer, nil
}

func Encrypt(key []byte, plaintext string) (string, error) {
  block, err := aes.NewCipher(key)
  if err != nil {
    return "", err
  }

  ciphertext := make([]byte, aes.BlockSize+len(plaintext))
  iv := ciphertext[:aes.BlockSize]
  if _, err := io.ReadFull(rand.Reader, iv); err != nil {
    return "", err
  }

  stream := cipher.NewCFBEncrypter(block, iv)
  stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

  return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(key []byte, ciphertext string) (string, error) {
  block, err := aes.NewCipher(key)
  if err != nil {
    return "", err
  }

  ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
  if err != nil {
    return "", err
  }

  iv := ciphertextBytes[:aes.BlockSize]
  ciphertextBytes = ciphertextBytes[aes.BlockSize:]

  stream := cipher.NewCFBDecrypter(block, iv)
  stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

  return string(ciphertextBytes), nil
}
