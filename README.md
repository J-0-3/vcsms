# vcsms
VCSMS (Very Cryptographically Secure Messaging Service) is an end-to-end encrypted messaging app which I am developed to learn about implementing and using common cryptographic algorithms.
The app is designed to be self-hostable and trustless so that any public instance can be used without requiring any trust in the owner.
The cryptographic algorithms used in the app (RSA, Diffie Hellman, AES and SHA) are all implemented from scratch.
 The app uses curses for its GUI but the library's API is designed to be simple to use if one should wish to implement their own client program (start 
 with [vcsms.client](vcsms/client.py) and read the docs). 

 ## Disclaimer
 This application is purely a personal project, and is not intended for real use in handling sensitive data. The cryptographic implementations have **not** been approved, tested or certified by any professional organisations, and may well contain flaws or vulnerabilities which I have not identified. 

## Cryptography
The application uses RSA to sign data and Diffie-Hellman public keys to prevent MitM attacks and to maintain end-to-end integrity, and AES to encrypt the data itself. The identifiers used for users are a hexadecimal representation of a SHA256 fingerprint of their RSA public key, allowing for assurance that their public key is actually theirs (as an alternative to PKI or a web of trust, which would be impractical to implement without any existing infrastructure). Every time a message is sent, a new signed diffie-hellman key exchange is performed between the communicating parties, meaning that the same encryption key is never used twice. Signed data has a timestamp and TTL field included to prevent replay attacks being successful, and all encrypted data has a SHA256 HMAC appended to prevent padding oracle attacks.
