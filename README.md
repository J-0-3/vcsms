# vcsms
VCSMS (Very Cryptographically Secure Messaging Service) is an end-to-end encrypted messaging app which I am developing for my A level project.
The app is designed to be self-hostable and trustless so that any public instance can be used without requiring any trust in the owner.
The cryptographic algorithms used in the app (RSA, Diffie Hellman, AES and SHA) are all implemented from scratch.
 The app uses curses for its GUI but the library's API is designed to be simple to use if one should wish to implement their own client program (start 
 with [vcsms.client](vcsms/client.py) and read the docs). 

 ## Disclaimer
 This application is purely a personal project, and is not intended for real use in handling sensitive data. The cryptographic implementations have **not** been approved, tested or certified by any professional organisations, and may well contain flaws or vulnerabilities which I have not identified. 
