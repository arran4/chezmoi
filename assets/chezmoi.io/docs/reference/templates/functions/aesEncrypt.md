# `aesEncrypt` *keyHex* *plaintext*

`aesEncrypt` encrypts *plaintext* using AES-GCM with *keyHex* and returns a Base64 encoded ciphertext. Use `aesDecrypt` to decrypt the result.

!!! example
    ```
    {{ aesDecrypt "000102030405060708090a0b0c0d0e0f" (aesEncrypt "000102030405060708090a0b0c0d0e0f" "secret") }}
    ```

    ```
    {{ aesDecrypt (argon2Key "password" "salt" 32) (aesEncrypt (argon2Key "password" "salt" 32) "secret") }}
    ```
