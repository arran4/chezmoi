# `edit-template` [*template*...]

Edit templates in the `.chezmoitemplates` directory using the configured
editor. If no templates are specified, the `.chezmoitemplates` directory
itself is opened in the editor.

## Flags

### `-m`, `--make`

Create templates if they do not exist.

### `-a`, `--apply`

Apply changes after editing.

## Examples

```sh
chezmoi edit-template foo.tmpl
chezmoi edit-template -m bar.tmpl
chezmoi edit-template -a baz.tmpl
```
