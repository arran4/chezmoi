# `aesDecrypt` *keyHex* *ciphertext*

`aesDecrypt` decrypts Base64 encoded *ciphertext* previously created with `aesEncrypt` using the AES key given by *keyHex*.

!!! example
    ```
    {{ aesDecrypt "000102030405060708090a0b0c0d0e0f" (aesEncrypt "000102030405060708090a0b0c0d0e0f" "secret") }}
    ```

    ```
    {{ aesDecrypt (argon2Key "password" "salt" 32) (aesEncrypt (argon2Key "password" "salt" 32) "secret") }}
    ```
