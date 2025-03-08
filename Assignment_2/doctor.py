import socket
import json
import random
import hashlib
import time
from math import gcd
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

p = 340282366920938463463374607431768211507
g = 5

def modinv(a, m):
    def egcd(a,b):
        if a==0:
            return (b,0,1)
        g_val,x,y= egcd(b%a,a)
        return (g_val, y-(b//a)*x,x)
    g_val,x,y= egcd(a,m)
    if g_val!=1:
        raise Exception("No modular inverse.")
    return x%m

def elgamal_keygen():
    x= random.randrange(2,p-1)
    y= pow(g,x,p)
    return x,y

def elgamal_encrypt(m, y_public):
    k= random.randrange(2,p-1)
    c1= pow(g,k,p)
    c2= (m* pow(y_public,k,p))%p
    return (c1,c2)

def elgamal_decrypt(c1c2, x_private):
    (c1,c2)= c1c2
    s= pow(c1,x_private,p)
    s_inv= modinv(s,p)
    return (c2*s_inv)%p

def sha256_int(data: bytes)->int:
    return int.from_bytes(hashlib.sha256(data).digest(), byteorder='big')

def elgamal_sign(msg_int, x_private):
    while True:
        k= random.randrange(2,p-1)
        if gcd(k,p-1)==1:
            break
    r= pow(g,k,p)
    k_inv= modinv(k,p-1)
    s= (k_inv*(msg_int - x_private*r))%(p-1)
    return (r,s)

def elgamal_verify(msg_int, signature, y_public):
    (r,s)= signature
    if not (0<r<p):
        return False
    left= (pow(y_public,r,p)* pow(r,s,p))%p
    right= pow(g,msg_int,p)
    return (left== right)

def aes_encrypt(key_32: bytes, plaintext: bytes)-> bytes:
    iv= os.urandom(16)
    cipher= AES.new(key_32, AES.MODE_CBC, iv)
    ct= cipher.encrypt(pad(plaintext, AES.block_size))
    return iv+ ct

def aes_decrypt(key_32: bytes, iv_ct: bytes)-> bytes:
    iv= iv_ct[:16]
    ct= iv_ct[16:]
    cipher= AES.new(key_32, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

class Doctor:

    def __init__(self):
        print("[Doctor] Using prime p,g for ElGamal.")
        self.x_private, self.y_public= elgamal_keygen()
        print(f"[Doctor] x_private = {self.x_private}, y_public = {self.y_public}")

        self.server_socket= None
        self.ephemeral_keys= {}
        self.patients= {}
        self.MAX_TS_DIFF= 20  
        self.current_broadcast_in_progress= False
        self.x_for_rekey= 2  

    def start_server(self, host="127.0.0.1", port=65432):
        self.server_socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        print(f"[Doctor] Listening to Host:Port - {host}:{port} ")

    def accept_new_patient(self):

        print("[Doctor] Waiting for new patient")
        self.server_socket.settimeout(5.0)
        try:
            conn, addr= self.server_socket.accept()
        except socket.timeout:
            print("[Doctor] Time out stopped waiting")
            self.server_socket.settimeout(None)
            return
        self.server_socket.settimeout(None)
        print(f"[Doctor]   Connected from {addr}")

        doc_info= {
          "p": p,
          "g": g,
          "doctor_id": "DoctorGWN",
          "doctor_pub": self.y_public
        }
        conn.sendall(json.dumps(doc_info).encode())

        data= conn.recv(4096)
        if not data:
            conn.close()
            return
        auth_req= json.loads(data.decode())
        print("[Doctor]   Received auth_req -", auth_req)

        TSi_val= int(auth_req["TSi"])
        now_val= int(time.time())
        diff= abs(now_val - TSi_val)
        print(f"[Doctor]   TSi={TSi_val}, now={now_val}, difference={diff}")
        if diff> self.MAX_TS_DIFF:
            print("[Doctor]  TSi limit exceeded. Not accepting that patient")
            conn.close()
            return
        print(f"[Doctor]    TSi accepted (within {self.MAX_TS_DIFF}s).")

        resp= self.handle_auth_request(auth_req)
        conn.sendall(json.dumps(resp).encode())
        if resp.get("status")!="ok":
            conn.close()
            return

        data2= conn.recv(4096)
        if not data2:
            conn.close()
            return
        final_req= json.loads(data2.decode())
        print("[Doctor]   final_req -", final_req)

        if self.verify_final(final_req):
            pid= final_req["patient_id"]
            SK= self.compute_session_key(final_req)
            print(f"[Doctor]   Session key - {SK.hex()} for {pid}")
            self.patients[pid]= {
                "conn": conn,
                "session_key": SK,
                "active": True
            }
            conn.sendall(json.dumps({"status":"ok","msg":"Session established"}).encode())
            print(f"[Doctor]  Session established with {pid} ")

        else:
            conn.sendall(json.dumps({"status":"error","msg":"Session mismatch"}).encode())
            conn.close()

    def handle_auth_request(self, req):
        data_str= f"{req['TSi']}|{req['RNi']}|{req['IDGWN']}|{req['enc_session_key']}"
        msg_int= sha256_int(data_str.encode())
        (r,s)= tuple(req["signature"])
        patient_pub= req["patient_pub"]
        if not elgamal_verify(msg_int, (r,s), patient_pub):
            return {"status":"error","reason":"signature invalid"}

        (c1,c2)= req["enc_session_key"]
        ephemeral= elgamal_decrypt((c1,c2), self.x_private)
        print(f"[Doctor] ephemeral_key - {ephemeral}")
        self.ephemeral_keys[req["patient_id"]]= ephemeral

        TSGWN_val= int(time.time())
        TSGWN_str= str(TSGWN_val)
        RNGWN= random.randint(1000,9999)
        c_for_pat= elgamal_encrypt(ephemeral, patient_pub)
        c_list= list(c_for_pat)
        sign_str= f"{TSGWN_str}|{RNGWN}|{req['patient_id']}|{c_list}"
        sign_int= sha256_int(sign_str.encode())
        (r2,s2)= elgamal_sign(sign_int, self.x_private)

        return {
          "opcode": 20,
          "status":"ok",
          "TSGWN": TSGWN_str,
          "RNGWN": RNGWN,
          "IDDi": req["patient_id"],
          "enc_session_key_for_patient": c_list,
          "signature2": [r2,s2],
          "TSi": req["TSi"],
          "RNi": req["RNi"]
        }

    def verify_final(self, final_req):
        pid= final_req["patient_id"]
        ephemeral= self.ephemeral_keys.get(pid)
        if ephemeral is None:
            return False
        SK= self.compute_session_key(final_req)
        TS_prime= final_req["TS_prime"]
        local_SKV= hashlib.sha256(SK + TS_prime.encode()).hexdigest()
        return (local_SKV== final_req["SKV"])

    def compute_session_key(self, final_req):
        pid= final_req["patient_id"]
        ephemeral= self.ephemeral_keys[pid]
        TSi= final_req["TSi"]
        TSGWN= final_req["TSGWN"]
        RNi= final_req["RNi"]
        RNGWN= final_req["RNGWN"]
        IDi= pid
        IDGWN= "DoctorGWN"
        concat_str= f"{ephemeral}{TSi}{TSGWN}{RNi}{RNGWN}{IDi}{IDGWN}"
        return hashlib.sha256(concat_str.encode()).digest()

    def compute_group_key(self, active_only=True):
        relevant_pids = [pid for pid,info in self.patients.items() if info.get("active")]
        if not relevant_pids:
            print("[Doctor] No active patients so no group key generated")
            return None, []
        combined= b""
        for pid in relevant_pids:
            combined+= self.patients[pid]["session_key"]
        combined+= str(self.x_private).encode()
        GK= hashlib.sha256(combined).digest()
        print(f"[Doctor] group key - {GK.hex()} for group - {relevant_pids}")
        return GK, relevant_pids

    def distribute_group_key(self, GK: bytes, group_pids):
        if not GK:
            return
        print("[Doctor] [Opcode 30] Distributing GK to group -", group_pids)
        for pid in group_pids:
            info= self.patients[pid]
            enc_GK= aes_encrypt(info["session_key"], GK)
            msg_dict= {
              "opcode":30,
              "encrypted_GK": enc_GK.hex()
            }
            info["conn"].sendall(json.dumps(msg_dict).encode())
            print(f"[Doctor]   Sent GK to {pid}")

    def broadcast_message(self, GK: bytes, group_pids, plaintext: str):
        if not GK:
            return
        print(f"[Doctor] [Opcode 40] Broadcasting - '{plaintext}' to group - {group_pids}")
        enc_msg= aes_encrypt(GK, plaintext.encode())
        msg_dict= {
          "opcode":40,
          "encrypted_msg": enc_msg.hex()
        }
        for pid in group_pids:
            info= self.patients[pid]
            info["conn"].sendall(json.dumps(msg_dict).encode())
            print(f"[Doctor]   Sent broadcast to {pid}")

    def main_loop(self):
        self.current_broadcast_in_progress= False
        last_group_pids = []  
        while True:
            print("1) Accept new patient")
            print("2) Broadcast message")
            print("3) Mark a patient offline")
            print("4) Quit")
            choice= input("Enter choice: ")
            if choice=="1":
                self.accept_new_patient()
            elif choice=="2":
                new_GK, new_group_pids= self.compute_group_key(active_only=True)
                if not new_GK:
                    continue
                old_set= set(last_group_pids)
                new_set= set(new_group_pids)
                diff_len= len(new_set - old_set)
                if diff_len>= self.x_for_rekey:
                    self.distribute_group_key(new_GK, new_group_pids)
                    msg= input("Broadcast message - ")
                    self.current_broadcast_in_progress= True
                    self.broadcast_message(new_GK, new_group_pids, msg)
                    self.current_broadcast_in_progress= False
                    last_group_pids= new_group_pids
                else:
                    if not last_group_pids:
                        self.distribute_group_key(new_GK, new_group_pids)
                        msg= input("Broadcast message - ")
                        self.current_broadcast_in_progress= True
                        self.broadcast_message(new_GK, new_group_pids, msg)
                        self.current_broadcast_in_progress= False
                        last_group_pids= new_group_pids
                    else:
                        msg= input("Broadcast message - ")
                        self.current_broadcast_in_progress= True
                        self.distribute_group_key(new_GK, new_group_pids)
                        self.broadcast_message(new_GK, new_group_pids, msg)
                        self.current_broadcast_in_progress= False
                        last_group_pids= new_group_pids

            elif choice=="3":
                print("[Doctor] Current patients -", list(self.patients.keys()))
                pid= input("Which patient ID to mark offline? ")
                if pid in self.patients:
                    self.patients[pid]["active"]= False
                    print(f"[Doctor] Marked {pid} offline won't receive future broadcasts.")
                else:
                    print("[Doctor] No such patient.")
            elif choice=="4":
                print("[Doctor] Quitting.")
                for pid,info in self.patients.items():
                    info["conn"].close()
                if self.server_socket:
                    self.server_socket.close()
                break
            else:
                print("[Doctor] Invalid choice.")

def main():
    doc= Doctor()
    doc.start_server()
    doc.main_loop()

if __name__=="__main__":
    main()
