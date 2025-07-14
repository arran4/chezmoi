package cmd

import (
	"errors"
	"io/fs"

	"github.com/spf13/cobra"

	"github.com/twpayne/chezmoi/internal/chezmoi"
)

type editIgnoreCmdConfig struct {
	make  bool
	apply bool
}

func (c *Config) newEditIgnoreCmd() *cobra.Command {
	editIgnoreCmd := &cobra.Command{
		Use:     "edit-ignore",
		Short:   "Edit the .chezmoiignore file",
		Long:    mustLongHelp("edit-ignore"),
		Example: example("edit-ignore"),
		Args:    cobra.NoArgs,
		RunE:    c.runEditIgnoreCmd,
		Annotations: newAnnotations(
			doesNotRequireValidConfig,
			modifiesSourceDirectory,
			modifiesDestinationDirectory,
			persistentStateModeReadOnly,
			runsCommands,
		),
	}

	editIgnoreCmd.Flags().
		BoolVarP(&c.editIgnore.make, "make", "m", c.editIgnore.make, "Makes .chezmoiignore if it does not exist")
	editIgnoreCmd.Flags().BoolVarP(&c.editIgnore.apply, "apply", "a", c.editIgnore.apply, "Apply after editing")
	return editIgnoreCmd
}

func (c *Config) runEditIgnoreCmd(cmd *cobra.Command, args []string) error {
	ignoreAbsPath := c.SourceDirAbsPath.JoinString(".chezmoiignore")
	if _, err := c.sourceSystem.Stat(ignoreAbsPath); errors.Is(err, fs.ErrNotExist) {
		if !c.editIgnore.make {
			return err
		}
		if err := chezmoi.MkdirAll(c.sourceSystem, ignoreAbsPath.Dir(), fs.ModePerm); err != nil &&
			!errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := c.sourceSystem.WriteFile(ignoreAbsPath, nil, 0o666&^c.Umask); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := c.runEditor([]string{ignoreAbsPath.String()}); err != nil {
		return err
	}
	if c.editIgnore.apply {
		if err := c.applyArgs(cmd.Context(), c.destSystem, c.DestDirAbsPath, noArgs, applyArgsOptions{
			cmd:          cmd,
			recursive:    true,
			filter:       c.Edit.filter,
			init:         c.Edit.init,
			umask:        c.Umask,
			preApplyFunc: c.defaultPreApplyFunc,
		}); err != nil {
			return err
		}
	}
	return nil
}
