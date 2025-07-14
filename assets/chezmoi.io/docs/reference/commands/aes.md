# `encryption aes`

Interact with AES encryption using a hex key or a key derived from a password with Argon2.

## Subcommands

### `encryption aes encrypt` [*file*|`-`|*text*...]

Encrypt files, strings, or stdin. The ciphertext is written in base64.

#### `--key` _hex_

Use the supplied hex encoded key for encryption.

#### `-p`, `--password`

Prompt for a password and derive the key using Argon2.
Exactly one of `--key` or `--password` must be provided.

#### `--salt` _string_

Salt to use with Argon2 when `--password` is given.

#### `--keylen` _int_

#### `-d`, `--delete`

Delete source files after encryption.

#### `-s`, `--string`

Treat each argument as plaintext instead of a path.

#### `--keylen` _int_

Length of the derived key in bytes when `--password` is given (default 32).

### `encryption aes decrypt` [*file*|`-`|*text*...]

Decrypt files, strings, or stdin containing base64 encoded ciphertext.

The flags have the same meaning as in `encryption aes encrypt`.
Exactly one of `--key` or `--password` must be provided.

## Examples

```sh
chezmoi encryption aes encrypt --key 000102030405060708090a0b0c0d0e0f secret.txt > secret.txt.aes
chezmoi encryption aes decrypt --key 000102030405060708090a0b0c0d0e0f secret.txt.aes > secret.txt
```

```sh
chezmoi encryption aes encrypt --password --salt mysalt secret.txt > secret.txt.aes
chezmoi encryption aes decrypt --password --salt mysalt secret.txt.aes > secret.txt
```
