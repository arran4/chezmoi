# `argon2Key` *password* *salt* *length*

`argon2Key` derives a key of *length* bytes from *password* and *salt* using Argon2id and returns it encoded as hex.

!!! example
    ```
    {{ argon2Key "password" "salt" 32 }}
    ```
