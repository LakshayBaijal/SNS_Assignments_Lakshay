import socket
import json
import random
import hashlib
import time
from math import gcd
import os
import threading

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def modinv(a,m):
    def egcd(a,b):
        if a==0:
            return (b,0,1)
        g_val,x,y= egcd(b%a,a)
        return (g_val, y - (b // a)*x, x)
    g_val,x,y= egcd(a,m)
    if g_val!=1:
        raise Exception("No mod inverse.")
    return x%m

def elgamal_keygen(p, g):
    x= random.randrange(2,p-1)
    y= pow(g,x,p)
    return x,y

def elgamal_encrypt(m, p, g, y_public):
    k= random.randrange(2,p-1)
    c1= pow(g,k,p)
    c2= (m* pow(y_public,k,p))%p
    return (c1,c2)

def elgamal_decrypt(c1c2, p, x_private):
    c1,c2= c1c2
    s= pow(c1,x_private,p)
    s_inv= modinv(s,p)
    return (c2*s_inv)%p

def sha256_int(data: bytes)->int:
    return int.from_bytes(hashlib.sha256(data).digest(), byteorder='big')

def elgamal_sign(msg_int, p, g, x_private):
    while True:
        k= random.randrange(2,p-1)
        if gcd(k,p-1)==1:
            break
    r= pow(g,k,p)
    k_inv= modinv(k,p-1)
    s= (k_inv*(msg_int - x_private*r))%(p-1)
    return (r,s)

def elgamal_verify(msg_int, p, g, signature, y_public):
    (r,s)= signature
    if not(0<r<p):
        return False
    left= (pow(y_public,r,p)* pow(r,s,p))%p
    right= pow(g,msg_int,p)
    return (left== right)

def aes_decrypt(key_32: bytes, iv_ct: bytes)-> bytes:
    iv= iv_ct[:16]
    ct= iv_ct[16:]
    cipher= AES.new(key_32, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

class Patient2:

    def __init__(self):
        self.p= None
        self.g= None
        self.doctor_pub= None
        self.doctor_id= None
        self.x_private= None
        self.y_public= None
        self.ephemeral= None
        self.SK= None
        self.GK= None
        self.sock= None

    def connect_to_doctor(self, host="127.0.0.1", port=65432):
        print(f"[Patient2] Connecting to doctor with host:port {host}:{port}")
        self.sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        data= self.sock.recv(4096)
        doc_info= json.loads(data.decode())
        print("[Patient2] doc info -", doc_info)
        self.p= doc_info["p"]
        self.g= doc_info["g"]
        self.doctor_pub= doc_info["doctor_pub"]
        self.doctor_id= doc_info["doctor_id"]

        self.x_private, self.y_public= elgamal_keygen(self.p, self.g)
        print(f"[Patient2] x_private={self.x_private}, y_public={self.y_public}")

        auth_req= self.build_auth_req()
        print("[Patient2] sending auth_req with TSi, ephemeral")
        self.sock.sendall(json.dumps(auth_req).encode())

        data2= self.sock.recv(4096)
        if not data2:
            self.sock.close()
            return
        doc_resp= json.loads(data2.decode())
        print("[Patient2] doc_resp -", doc_resp)
        if doc_resp.get("status")!="ok":
            print("[Patient2] error -", doc_resp.get("reason"))
            self.sock.close()
            return

        if not self.process_doc_response(doc_resp):
            print("[Patient2] ephemeral mismatch - closing.")
            self.sock.close()
            return

        final_req= self.finalize_handshake(doc_resp)
        print("[Patient2] sending final verifier.")
        self.sock.sendall(json.dumps(final_req).encode())

        data3= self.sock.recv(4096)
        final_ack= json.loads(data3.decode())
        print("[Patient2] final_ack -", final_ack)
        if final_ack.get("status")=="ok":
            print("[Patient2]  Session Established ")
            print(f"[Patient2]   SK - {self.SK.hex()}")
            t= threading.Thread(target=self.listen_loop, daemon=True)
            t.start()
            self.chat_loop()
        else:
            print("[Patient2] mismatch - closing.")
            self.sock.close()

    def build_auth_req(self):
        TSi_val= int(time.time())
        TSi_str= str(TSi_val)
        RNi= random.randint(1000,9999)
        self.ephemeral= random.randint(2,self.p-1)

        print(f"[Patient2] TSi={TSi_val}, ephemeral={self.ephemeral}.")
        time.sleep(2) 

        (c1,c2)= elgamal_encrypt(self.ephemeral, self.p,self.g,self.doctor_pub)
        c_list= [c1,c2]
        data_str= f"{TSi_str}|{RNi}|{self.doctor_id}|{c_list}"
        msg_int= sha256_int(data_str.encode())
        (r,s)= elgamal_sign(msg_int, self.p,self.g, self.x_private)

        auth_req= {
            "opcode":10,
            "TSi": TSi_str,
            "RNi": RNi,
            "IDGWN": self.doctor_id,
            "enc_session_key": c_list,
            "signature": [r,s],
            "patient_pub": self.y_public,
            "patient_id": "Patient2"
        }
        return auth_req

    def process_doc_response(self, resp):
        c_list= resp["enc_session_key_for_patient"]
        c1,c2= c_list
        dec_ephem= elgamal_decrypt((c1,c2), self.p, self.x_private)
        print(f"[Patient2] ephemeral decrypted - {dec_ephem}")
        if dec_ephem!= self.ephemeral:
            return False
        sign_str= f"{resp['TSGWN']}|{resp['RNGWN']}|{resp['IDDi']}|{c_list}"
        msg_int= sha256_int(sign_str.encode())
        (r2,s2)= resp["signature2"]
        if not elgamal_verify(msg_int, self.p,self.g, (r2,s2), self.doctor_pub):
            return False
        self.TSGWN= resp["TSGWN"]
        self.RNGWN= resp["RNGWN"]
        return True

    def finalize_handshake(self, doc_resp):
        ephemeral= self.ephemeral
        TSi= doc_resp["TSi"]
        TSGWN= doc_resp["TSGWN"]
        RNi= doc_resp["RNi"]
        RNGWN= doc_resp["RNGWN"]
        IDi= "Patient2"
        IDGWN= self.doctor_id
        concat_str= f"{ephemeral}{TSi}{TSGWN}{RNi}{RNGWN}{IDi}{IDGWN}"
        SK_bytes= hashlib.sha256(concat_str.encode()).digest()
        self.SK= SK_bytes

        TS_prime_val= int(time.time())
        TS_prime_str= str(TS_prime_val)
        local_SKV= hashlib.sha256(SK_bytes + TS_prime_str.encode()).hexdigest()

        final_req= {
            "patient_id": IDi,
            "TSi": TSi,
            "TSGWN": TSGWN,
            "RNi": RNi,
            "RNGWN": RNGWN,
            "SKV": local_SKV,
            "TS_prime": TS_prime_str
        }
        return final_req

    def listen_loop(self):
        while True:
            try:
                data= self.sock.recv(4096)
                if not data:
                    print("[Patient2] Doctor closed.")
                    break
                msg_dict= json.loads(data.decode())
                self.handle_incoming_msg(msg_dict)
            except:
                break
        self.sock.close()

    def handle_incoming_msg(self, msg_dict):
        opcode= msg_dict.get("opcode")
        if opcode==30:
            print("[Patient2] Received group key. Decrypting with SK.")
            enc_GK_hex= msg_dict["encrypted_GK"]
            enc_GK= bytes.fromhex(enc_GK_hex)
            try:
                GK_bytes= self.aes_decrypt_256(self.SK, enc_GK)
                self.GK= GK_bytes
                print(f"[Patient2]   GK - {self.GK.hex()}")
            except:
                print("[Patient2]   ERROR: decrypt GK fail.")
        elif opcode==40:
            if not self.GK:
                print("[Patient2] No GK can't decrypt broadcast.")
                return
            enc_hex= msg_dict["encrypted_msg"]
            enc= bytes.fromhex(enc_hex)
            try:
                raw= self.aes_decrypt_256(self.GK, enc)
                plaintext= raw.decode()
                print(f"[Patient2] BROADCAST - '{plaintext}'")
            except:
                print("[Patient2] ERROR - can't decrypt broadcast.")
        else:
            print("[Patient2] unknown ", msg_dict)

    def aes_decrypt_256(self, key_32: bytes, iv_cipher: bytes)-> bytes:
        iv= iv_cipher[:16]
        ciphertext= iv_cipher[16:]
        cipher= AES.new(key_32, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

    def chat_loop(self):
        print("[Patient2] You may type plaintext messages. 'bye' to end.")
        while True:
            msg= input("[Patient2] ")
            if not msg:
                msg= "(empty)"
            self.sock.sendall(msg.encode())
            if msg.strip().lower()=="bye":
                print("[Patient2] closing socket.")
                self.sock.close()
                break

def main():
    pat= Patient2()
    pat.connect_to_doctor("127.0.0.1",65432)

if __name__=="__main__":
    main()
