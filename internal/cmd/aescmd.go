package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"

	"github.com/twpayne/chezmoi/internal/chezmoi"
)

// AES encryption command configuration.
type aesCmdConfig struct {
	decrypt aesDecryptCmdConfig
	encrypt aesEncryptCmdConfig
}

type aesEncryptCmdConfig struct {
	key      string
	password bool
	salt     string
	keyLen   int
	delete   bool
	text     bool
}

type aesDecryptCmdConfig struct {
	key      string
	password bool
	salt     string
	keyLen   int
	delete   bool
	text     bool
}

func (c *Config) newAESCmd() *cobra.Command {
	aesCmd := &cobra.Command{
		Use:   "aes",
		Args:  cobra.NoArgs,
		Short: "Interact with AES encryption",
		Annotations: newAnnotations(
			persistentStateModeReadOnly,
		),
	}

	aesDecryptCmd := &cobra.Command{
		Use:   "decrypt [file|-|text...]",
		Short: "Decrypt file, string, or stdin",
		RunE:  c.runAESDecryptCmd,
		Annotations: newAnnotations(
			persistentStateModeReadOnly,
		),
	}
	aesDecryptCmd.Flags().StringVar(&c.aes.decrypt.key, "key", c.aes.decrypt.key, "Hex-encoded key")
	aesDecryptCmd.Flags().BoolVarP(&c.aes.decrypt.password, "password", "p", c.aes.decrypt.password, "Derive key from password using argon2")
	aesDecryptCmd.Flags().StringVar(&c.aes.decrypt.salt, "salt", c.aes.decrypt.salt, "Salt for argon2")
	aesDecryptCmd.Flags().IntVar(&c.aes.decrypt.keyLen, "keylen", c.aes.decrypt.keyLen, "Key length for argon2")
	aesDecryptCmd.Flags().BoolVarP(&c.aes.decrypt.delete, "delete", "d", c.aes.decrypt.delete, "Delete source files")
	aesDecryptCmd.Flags().BoolVarP(&c.aes.decrypt.text, "string", "s", c.aes.decrypt.text, "Decrypt arguments as strings")
	aesCmd.AddCommand(aesDecryptCmd)

	aesEncryptCmd := &cobra.Command{
		Use:   "encrypt [file|-|text...]",
		Short: "Encrypt file, string, or stdin",
		RunE:  c.runAESEncryptCmd,
		Annotations: newAnnotations(
			persistentStateModeReadOnly,
		),
	}
	aesEncryptCmd.Flags().StringVar(&c.aes.encrypt.key, "key", c.aes.encrypt.key, "Hex-encoded key")
	aesEncryptCmd.Flags().BoolVarP(&c.aes.encrypt.password, "password", "p", c.aes.encrypt.password, "Derive key from password using argon2")
	aesEncryptCmd.Flags().StringVar(&c.aes.encrypt.salt, "salt", c.aes.encrypt.salt, "Salt for argon2")
	aesEncryptCmd.Flags().IntVar(&c.aes.encrypt.keyLen, "keylen", c.aes.encrypt.keyLen, "Key length for argon2")
	aesEncryptCmd.Flags().BoolVarP(&c.aes.encrypt.delete, "delete", "d", c.aes.encrypt.delete, "Delete source files")
	aesEncryptCmd.Flags().BoolVarP(&c.aes.encrypt.text, "string", "s", c.aes.encrypt.text, "Encrypt arguments as strings")
	aesCmd.AddCommand(aesEncryptCmd)

	return aesCmd
}

func (c *Config) aesKey(password bool, keyHex, salt string, keyLen int, confirm bool) ([]byte, error) {
	if password {
		pass, err := c.readPassword("Enter password: ", "password")
		if err != nil {
			return nil, err
		}
		if confirm {
			confirmPass, err := c.readPassword("Confirm password: ", "password")
			if err != nil {
				return nil, err
			}
			if pass != confirmPass {
				return nil, errors.New("passwords didn't match")
			}
		}
		return argon2.IDKey([]byte(pass), []byte(salt), 1, 64*1024, 4, uint32(keyLen)), nil
	}
	if keyHex == "" {
		return nil, errors.New("key must be set")
	}
	return hex.DecodeString(keyHex)
}

func aesEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(buf, ciphertext)
	return buf, nil
}

func aesDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	data := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	n, err := base64.StdEncoding.Decode(data, ciphertext)
	if err != nil {
		return nil, err
	}
	data = data[:n]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := data[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, data[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (c *Config) aesProcess(args []string, text bool, delete bool, f func([]byte) ([]byte, error)) error {
	if text {
		for _, arg := range args {
			output, err := f([]byte(arg))
			if err != nil {
				return err
			}
			if err := c.writeOutput(output); err != nil {
				return err
			}
		}
		return nil
	}

	if len(args) == 0 {
		input, err := io.ReadAll(c.stdin)
		if err != nil {
			return err
		}
		output, err := f(input)
		if err != nil {
			return err
		}
		return c.writeOutput(output)
	}

	for _, arg := range args {
		var (
			input   []byte
			err     error
			absPath chezmoi.AbsPath
			isFile  bool
		)
		if arg == "-" {
			input, err = io.ReadAll(c.stdin)
		} else {
			absPath, err = chezmoi.NewAbsPathFromExtPath(arg, c.homeDirAbsPath)
			if err == nil {
				input, err = c.baseSystem.ReadFile(absPath)
				isFile = true
			}
		}
		if err != nil {
			return err
		}
		output, err := f(input)
		if err != nil {
			return err
		}
		if err := c.writeOutput(output); err != nil {
			return err
		}
		if delete && isFile {
			if err := c.baseSystem.RemoveAll(absPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) runAESEncryptCmd(cmd *cobra.Command, args []string) error {
	keyLen := 32
	if c.aes.encrypt.keyLen != 0 {
		keyLen = c.aes.encrypt.keyLen
	}
	key, err := c.aesKey(c.aes.encrypt.password, c.aes.encrypt.key, c.aes.encrypt.salt, keyLen, c.aes.encrypt.password)
	if err != nil {
		return err
	}
	encrypt := func(plaintext []byte) ([]byte, error) {
		return aesEncrypt(key, plaintext)
	}
	return c.aesProcess(args, c.aes.encrypt.text, c.aes.encrypt.delete, encrypt)
}

func (c *Config) runAESDecryptCmd(cmd *cobra.Command, args []string) error {
	keyLen := 32
	if c.aes.decrypt.keyLen != 0 {
		keyLen = c.aes.decrypt.keyLen
	}
	key, err := c.aesKey(c.aes.decrypt.password, c.aes.decrypt.key, c.aes.decrypt.salt, keyLen, false)
	if err != nil {
		return err
	}
	decrypt := func(ciphertext []byte) ([]byte, error) {
		return aesDecrypt(key, ciphertext)
	}
	return c.aesProcess(args, c.aes.decrypt.text, c.aes.decrypt.delete, decrypt)
}
