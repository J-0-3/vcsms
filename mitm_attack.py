import socket
import random
from cryptographylib import rsa, sha256, dhke, aes256, utils
import signing
import argparse
dhke_group = dhke.group16_4096


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("addr", type=str)
    parser.add_argument("port", default=6000, type=int)
    parser.add_argument("-p", "--listen_port", default=4000, type=int)
    parser.add_argument("-d", "--dump", help="Dump captured keys and messages to directory", type=str)
    args = parser.parse_args()
    
    pub, priv = rsa.gen_keypair(2048)
    pub_exp = hex(pub[0])[2:].encode()
    pub_mod = hex(pub[1])[2:].encode()
    pubkey_hash = hex(sha256.hash(pub_exp + pub_mod))[2:].encode()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", args.listen_port))
    s.listen()
    
    print("Waiting for client to connect...")
    client, addr = s.accept()
    print("Client connected. Connecting to server...")
    server.connect((args.addr, args.port))

    exp, mod = server.recv(2048).split(b':')
    server_public_key = (int(exp, 16), int(mod, 16))
    
    if args.dump:
        with open(f"{args.dump}/server_rsa.pub", "wb") as f:
                f.write(exp + b"," + mod)
                
    client.send(pub_exp+b':'+pub_mod)
    h, exp, mod = client.recv(2048).split(b':')
    
    client_public_key = (int(exp, 16), int(mod, 16))
    
    if args.dump:
        with open(f"{args.dump}/client_rsa.pub", "wb") as f:
            f.write(exp + b"," + mod)
        with open(f"{args.dump}/client_id", "wb") as f:
            f.write(h)
            
    server.send(pubkey_hash + b':' + pub_exp + b':' + pub_mod)
    
    server_dh_pub, server_dh_pub_sig = server.recv(2048).split(b':')
    
    if args.dump:
        with open(f"{args.dump}/server_dhke.pub", "wb") as f:
            f.write(server_dh_pub)
    
        with open(f"{args.dump}/server_dhke.pub.sig", "wb") as f:
            f.write(server_dh_pub_sig)
            
    evil_dh_priv = random.randrange(1, dhke_group[1])
    evil_dh_pub = hex(dhke.generate_public_key(evil_dh_priv, dhke_group))[2:].encode()
    
    evil_signature = signing.sign(evil_dh_pub, priv)
    
    
    client.send(evil_dh_pub + b':' + evil_signature)
    client_dh_pub, client_dh_pub_sig = client.recv(2048).split(b':')
    client_shared_secret = dhke.calculate_shared_key(evil_dh_priv, int(client_dh_pub, 16), dhke_group)
    
    server.send(evil_dh_pub + b':' + evil_signature)
    server_shared_secret = dhke.calculate_shared_key(evil_dh_priv, int(server_dh_pub, 16), dhke_group)
        
    if args.dump:
        with open(f"{args.dump}/server_shared_secret", "w") as f:
            f.write(hex(server_shared_secret)[2:])
    
        with open(f"{args.dump}/client_shared_secret", "w") as f:
            f.write(hex(client_shared_secret)[2:])
    
    print("MITM attack completed.")
    client_session_key = sha256.hash(utils.i_to_b(client_shared_secret))
    server_session_key = sha256.hash(utils.i_to_b(server_shared_secret))
    aes_iv = 203740925691429429542835616606368968923
    
    if args.dump:
        with open(f"{args.dump}/client_encryption_key", "w") as f:
            f.write(hex(client_session_key)[2:])
        with open(f"{args.dump}/server_encryption_key", "w") as f:
            f.write(hex(server_session_key)[2:])

    message_from_client = client.recv(2048)
    plaintext = aes256.decrypt_cbc(message_from_client, client_session_key, aes_iv)
    print(f"client sent: {plaintext}")

    encrypted_for_server = aes256.encrypt_cbc(plaintext, server_session_key, aes_iv)
#     print("SENDING MESSAGE ON TO SERVER...")
    server.send(encrypted_for_server)