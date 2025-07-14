package cmd

import "github.com/spf13/cobra"

type encryptionCmdConfig struct{}

func (c *Config) newEncryptionCmd() *cobra.Command {
	encryptionCmd := &cobra.Command{
		Use:   "encryption",
		Short: "Encryption helpers",
		Args:  cobra.NoArgs,
		Annotations: newAnnotations(
			persistentStateModeReadOnly,
		),
	}
	if aesCmd := c.newAESCmd(); aesCmd != nil {
		encryptionCmd.AddCommand(aesCmd)
	}
	return encryptionCmd
}
