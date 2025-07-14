package cmd

import (
	"errors"
	"io/fs"

	"github.com/spf13/cobra"

	"github.com/twpayne/chezmoi/internal/chezmoi"
)

type editTemplateCmdConfig struct {
	make  bool
	apply bool
}

func (c *Config) newEditTemplateCmd() *cobra.Command {
	editTemplateCmd := &cobra.Command{
		Use:     "edit-template [template]...",
		Short:   "Edit templates in .chezmoitemplates",
		Long:    mustLongHelp("edit-template"),
		Example: example("edit-template"),
		Args:    cobra.ArbitraryArgs,
		RunE:    c.runEditTemplateCmd,
		Annotations: newAnnotations(
			doesNotRequireValidConfig,
			modifiesSourceDirectory,
			modifiesDestinationDirectory,
			persistentStateModeReadOnly,
			runsCommands,
		),
	}

	editTemplateCmd.Flags().
		BoolVarP(&c.editTemplate.make, "make", "m", c.editTemplate.make, "Make the target template file if it does not exist")
	editTemplateCmd.Flags().BoolVarP(&c.editTemplate.apply, "apply", "a", c.editTemplate.apply, "Apply after editing")

	return editTemplateCmd
}

func (c *Config) runEditTemplateCmd(cmd *cobra.Command, args []string) error {
	templatesDirAbsPath := c.SourceDirAbsPath.JoinString(".chezmoitemplates")

	editorArgs := make([]string, len(args))
	for i, arg := range args {
		templateAbsPath := templatesDirAbsPath.JoinString(arg)
		if _, err := c.sourceSystem.Stat(templateAbsPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if !c.editTemplate.make {
					return err
				}
				if err := chezmoi.MkdirAll(c.sourceSystem, templateAbsPath.Dir(), fs.ModePerm); err != nil &&
					!errors.Is(err, fs.ErrExist) {
					return err
				}
			} else if !errors.Is(err, fs.ErrExist) {
				return err
			}
		}
		editorArgs[i] = templateAbsPath.String()
	}
	if err := c.runEditor(editorArgs); err != nil {
		return err
	}
	if c.editTemplate.apply {
		if err := c.applyArgs(cmd.Context(), c.destSystem, c.DestDirAbsPath, noArgs, applyArgsOptions{
			cmd:          cmd,
			filter:       c.Edit.filter,
			init:         c.Edit.init,
			recursive:    true,
			umask:        c.Umask,
			preApplyFunc: c.defaultPreApplyFunc,
		}); err != nil {
			return err
		}
	}
	return nil
}
