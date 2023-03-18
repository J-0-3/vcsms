#!/usr/bin/env python3
import random
import socket
import threading
import argparse
import subprocess
import os
import sys

sys.path.append("..")
from vcsms.cryptography.exceptions import CryptographyException
from vcsms.improved_socket import ImprovedSocket
from vcsms.message_parser import MessageParser
from vcsms.cryptography import dhke, sha256, utils, aes256
from vcsms.client import OUTGOING_MESSAGE_TYPES
from vcsms.client import INCOMING_MESSAGE_TYPES
from vcsms import signing, keys

MESSAGE_PARSER = MessageParser(INCOMING_MESSAGE_TYPES, OUTGOING_MESSAGE_TYPES, {})

def forward(fsock: ImprovedSocket, tsock: ImprovedSocket):
    data = fsock.recv()
    tsock.send(data)
    return data

def mitm_handshake(c: ImprovedSocket, s: ImprovedSocket, c_privkey: tuple, s_privkey: tuple) -> tuple:
    forward(s, c)  # server sends pub key
    forward(c, s)  # client sends pub key
    m_dh_privkey = random.randrange(1, dhke.group16_4096[1]) 
    m_dh_pubkey, m_sig_c = signing.gen_signed_dh(m_dh_privkey, c_privkey, dhke.group14_2048)
    _, m_sig_s = signing.gen_signed_dh(m_dh_privkey, s_privkey, dhke.group14_2048)
    s_dh_packet = s.recv()  # server sends difhel pub
    try:
        s_dh_pubkey = int(s_dh_packet.split(b':')[0], 16)
    except ValueError:
        print("Server diffie hellman key malformed")
        return (0, 0)
    print("Server sent diffie hellman public key")
    s_secret = dhke.calculate_shared_key(m_dh_privkey, s_dh_pubkey, dhke.group14_2048) 
    s.send(hex(m_dh_pubkey)[2:].encode() + b':' + m_sig_c)  # diffie hellman key signed with client private
    c.send(hex(m_dh_pubkey)[2:].encode() + b':' + m_sig_s)  # diffie hellman key signed with server private
    c_dh_packet = c.recv()  # client sends difhel pub
    try:
        c_dh_pubkey = int(c_dh_packet.split(b':')[0], 16)
    except ValueError:
        print("Client diffie hellman key malformed")
        return (0, 0)
    print("Client sent diffie hellman public key")
    c_secret = dhke.calculate_shared_key(m_dh_privkey, c_dh_pubkey, dhke.group14_2048)
    s_key = sha256.hash(utils.i_to_b(s_secret))  # session key with server
    c_key = sha256.hash(utils.i_to_b(c_secret))  # session key with client
    challenge = s.recv()  # server sends encrypted challenge
    try:
        iv_hex, ciphertext_hex = challenge.split(b':')
        iv = int(iv_hex, 16)
        ciphertext = bytes.fromhex(ciphertext_hex.decode('utf-8'))
    except:
        print("Server sent malformed challenge")
        return (0, 0)
    print("Server sent encrypted challenge")
    try:
        answer = aes256.decrypt_cbc(ciphertext, s_key, iv)
    except CryptographyException:
        print("Failed to decrypt challenge")
        return (0, 0)
    s.send(answer.hex().encode('utf-8'))  # i reply with decrypted challenge
    c_challenge = aes256.encrypt_cbc(answer, c_key, iv)
    c.send(hex(iv)[2:].encode('utf-8') + b':' + c_challenge.hex().encode('utf-8'))  
    # i send challenge to client

    if s.recv() != b'OK':
        print("Server rejected challenge response")
        return (0, 0)
    print("Succeeded server challenge")
    c_response = c.recv()  # client responds with challenge answer
    try:
        c_answer = bytes.fromhex(c_response.decode('utf-8'))
    except:
        print("Client sent malformed challenge response")
        return (0, 0)
    if c_answer != answer:
        print("Client failed challenge")
        return (0, 0)
    c.send(b'OK')  # inform client they were correct
    print("Handshake completed successfully") 
    return (s_key, c_key)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("server_ip", type=str, help="The IP address of the server")
    parser.add_argument("-p", "--server_port", type=int, default=6000, help="The server's listening port")
    parser.add_argument("-P", "--listen_port", type=int, default=6000, help="The port to listen for connections on")
    parser.add_argument("-l", "--interface", type=str, default="127.0.0.1", help="The IP address of the interface to listen on")
    parser.add_argument("client_private", type=str, help="The file containing the client's private key")
    parser.add_argument("server_private", type=str, help="The file containing the server's private key")
    parser.add_argument("client_password", type=str, help="The client's master password")
    parser.add_argument("server_password", type=str, help="The server's master password")
    args = parser.parse_args()
    client_enc_key = keys.derive_key(args.client_password)
    server_enc_key = keys.derive_key(args.server_password)
    client_private_key = keys.load_key(args.client_private, client_enc_key)
    server_private_key = keys.load_key(args.server_private, server_enc_key)
    server_socket_raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    server_socket_raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket = ImprovedSocket(server_socket_raw)
    accept_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    accept_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    accept_socket.bind((args.interface, args.listen_port))
    accept_socket.listen(30)
    print(f"Listening for a connection on {args.interface}:{args.listen_port}...")
    c, addr = accept_socket.accept()
    print(f"Got connection from {addr}")
    client_socket = ImprovedSocket(c)
    client_socket.run()
    server_socket.connect(args.server_ip, args.server_port)
    server_socket.run()
    server_key, client_key = mitm_handshake(client_socket, server_socket, client_private_key, server_private_key)
    print("Generating random data...")
    random_data = random.randbytes(2048) 
    iv = random.randrange(2, 2**128)
    print("Encrypting data...")
    ciphertext = aes256.encrypt_cbc(random_data, random.randrange(2, 2*256), iv)
    print("Formatting ciphertext properly...")
    formatted_data = hex(iv)[2:].encode('utf-8') + b':' + ciphertext.hex().encode('utf-8')
    print("Sending encrypted data.")
    client_socket.send(formatted_data)
    response_iv, response_ciphertext = client_socket.recv().split(b':', 1)
    iv = int(response_iv, 16)
    ciphertext = bytes.fromhex(response_ciphertext.decode('utf-8')) 
    plaintext = aes256.decrypt_cbc(ciphertext, client_key, iv)
    print(f"Response received from client: {plaintext}")
    client_socket.close()
    server_socket.close()
