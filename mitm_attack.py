import socket
import random
from cryptographylib import rsa, sha256, dhke, aes256, utils
import signing

dhke_group = dhke.group16_4096


if __name__ == "__main__":
    pub, priv = rsa.gen_keypair(2048)
    pub_exp = hex(pub[0])[2:].encode()
    pub_mod = hex(pub[1])[2:].encode()
    pubkey_hash = hex(sha256.hash(pub_exp + pub_mod))[2:].encode()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 4000))
    s.listen()
    client, addr = s.accept()
    server.connect(("127.0.0.1", 6000))
    
    exp, mod = server.recv(2048).split(b':')
    server_public_key = (int(exp, 16), int(mod, 16))
    
    client.send(pub_exp+b':'+pub_mod)
    h, exp, mod = client.recv(2048).split(b':')
    
    client_public_key = (int(exp, 16), int(mod, 16))
    server.send(pubkey_hash + b':' + pub_exp + b':' + pub_mod)
    
    server_dh_pub, server_dh_pub_sig = server.recv(2048).split(b':')
    
    evil_dh_priv = random.randrange(1, dhke_group[1])
    evil_dh_pub = hex(dhke.generate_public_key(evil_dh_priv, dhke_group))[2:].encode()
    
    evil_signature = signing.sign(evil_dh_pub, priv)
    
    
    client.send(evil_dh_pub + b':' + evil_signature)
    
    client_dh_pub, client_dh_pub_sig = client.recv(2048).split(b':')
    
    client_encryption_key = dhke.calculate_shared_key(evil_dh_priv, int(client_dh_pub, 16), dhke_group)

    server.send(evil_dh_pub + b':' + evil_signature)
    
    server_encryption_key = dhke.calculate_shared_key(evil_dh_priv, int(server_dh_pub, 16), dhke_group)
        
#     print(f"""SERVER'S PUBLIC KEY: {server_public_key}\n
#           CLIENT'S PUBLIC KEY: {client_public_key}\n
#           SERVER DHKE PUBLIC KEY: {server_dh_pub}\n
#           DHKE SIGNATURE: {server_dh_pub_sig}\n
#           CLIENT DHKE PUBLIC KEY: {client_dh_pub}\n
#           DHKE SIGNATURE: {client_dh_pub_sig}\n""")
#     print(f"""ENCRYPTION KEY WITH CLIENT: {hex(client_encryption_key)}\n
#           ENCRYPTION KEY WITH SERVER: {hex(server_encryption_key)}""")
    
    print("MITM attack completed.")
    
    message_from_client = client.recv(2048)
    plaintext = aes256.decrypt_cbc(message_from_client, sha256.hash(utils.i_to_b(client_encryption_key)), 203740925691429429542835616606368968923)
    print(f"client sent: {plaintext}")

    encrypted_for_server = aes256.encrypt_cbc(plaintext, sha256.hash(utils.i_to_b(server_encryption_key)), 203740925691429429542835616606368968923)
#     print("SENDING MESSAGE ON TO SERVER...")
    server.send(encrypted_for_server)