from multiprocessing import context
import socket 
from OpenSSL import crypto
import enum
from time import sleep
import ssl
import threading
import sys
from sys import argv, stdout
import os
import signal
import _thread

thread_exit = threading.Event()

class MessageType(enum.Enum):
    CHAT_HELLO = 1
    CHAT_REPLY = 2
    CHAT_STARTTLS = 3
    CHAT_STARTTLS_ACK = 4
    CERTIFICATE_VERIFIED = 5
    CERTIFICATE_VERIFICATION_FAILED = 6
    CHAT_CLOSE = 7
    CHAT_STARTTLS_NOT_SUPPORTED=8

def server():
    
    #creates a new socket of IPV4 family and type STREAM
    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    #returns if the certificate was added successfully.
    trust_store = create_trust_store('./ca_cert.pem')
    
    #bind the socket to port 6000
    socket_obj.bind(('', 6000))
    
    #Enable a server to accept connections and allow upto 5 new connections
    socket_obj.listen(5)
    print('server listening')
    
    #Accept a connection. 
    unsecure_socket, _ = socket_obj.accept()
    print('connected with client')

    incoming_msg = unsecure_socket.recv(4096).decode('UTF-8')
    if incoming_msg == MessageType.CHAT_HELLO.name:
        response_msg = MessageType.CHAT_REPLY.name
        unsecure_socket.sendall(response_msg.encode())
        print("chat reply sent")
        incoming_msg = unsecure_socket.recv(4096).decode()
        print(incoming_msg)
        
        
        if incoming_msg == MessageType.CHAT_STARTTLS.name:
            print('chat_starttls rcvd')
            response_msg = MessageType.CHAT_STARTTLS_ACK.name
            unsecure_socket.send(response_msg.encode('UTF-8'))
            print('chat_starttls_ack sent')
            
            #Create a new SSL context that supports TLS.
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            
            #load the CA certificate used to verify other peers' certificates.
            ssl_context.load_verify_locations('./ca_cert.pem')
            
            #Load a private key and the corresponding certificate.
            ssl_context.load_cert_chain(certfile='./bob.pem', keyfile="./bob-rsa.pem")
            
            #peers' certificate should be verified
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            
            #wraps the unsecure_socket and returns an SSL socket is tied to the ssl_context, its settings and certificates.
            with ssl_context.wrap_socket(unsecure_socket, server_side=True, do_handshake_on_connect=True) as secured_sock: 
                print('secure conn estblsh')
                print(secured_sock.recv(1024).decode('UTF-8'))
                secured_sock.send('secure hello reply'.encode('UTF-8'))
                rcvd_msg = secured_sock.recv(1024).decode('UTF-8')
                if rcvd_msg == MessageType.CERTIFICATE_VERIFIED.name: 
                    print(rcvd_msg)
                    
                    #returns the DER-encoded form of the entire certificate as a sequence of bytes
                    server_cert = secured_sock.getpeercert(binary_form=True)
                    
                    #returns true if peers' certificate is genuine.
                    if certificate_verify(server_cert, trust_store) :
                        secured_sock.send(MessageType.CERTIFICATE_VERIFIED.name.encode('UTF-8'))
                        start_chat(secured_sock)
                        #print(secured_sock.recv(4096).decode('UTF-8'))
                    else: 
                        secured_sock.send(MessageType.CERTIFICATE_VERIFICATION_FAILED.name.encode('UTF-8'))
                        secured_sock.close()
                else:
                    print(rcvd_msg)
                    print('server certificate verification failed...terminate connection')
                    socket_obj.close()
        
        else:
            start_chat(unsecure_socket) 
        
    
    else: 
        print('connection failed')
        socket_obj.close()

    socket_obj.close()

def client(server_name): 
    #create socket object
    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    #get IP from hostname
    try:
        server_ip = socket.gethostbyname(server_name)
    except socket.gaierror:
        print("Error getting IP from hostname")
        exit()
        
    client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    client_ssl_context.load_cert_chain(certfile="./alice.pem",keyfile="./alice-rsa.pem")
    client_ssl_context.load_verify_locations('./ca_cert.pem')
    client_ssl_context.verify_mode = ssl.CERT_REQUIRED
    trust_store = create_trust_store('./ca_cert.pem')

    socket_obj.connect((server_ip, 6000))
    print('connection established with server')
    sent_msg =  MessageType.CHAT_HELLO.name
    socket_obj.send(sent_msg.encode())
    print('chat_hello sent')
    rcvd_msg = socket_obj.recv(4096).decode()
    
    if rcvd_msg == MessageType.CHAT_REPLY.name : 
        print('chat_reply rcvd')
        sent_msg = MessageType.CHAT_STARTTLS.name
        socket_obj.send(sent_msg.encode('UTF-8'))
        rcvd_msg = socket_obj.recv(4096).decode()
        print('chat_starttls sent')
        if rcvd_msg == MessageType.CHAT_STARTTLS_ACK.name:
            print('chat_starttls_ack rcvd')
            with client_ssl_context.wrap_socket(socket_obj, do_handshake_on_connect=True) as secured_sock:
                 print('secure conn established')
                 secured_sock.send('secure hello'.encode('UTF-8'))
                 print(secured_sock.recv(1024).decode('UTF-8'))
                 
                 server_cert = secured_sock.getpeercert(binary_form = True)
                 #print(server_cert)
                 if certificate_verify(server_cert, trust_store): 
                    secured_sock.send(MessageType.CERTIFICATE_VERIFIED.name.encode('UTF-8'))
                    rcvd_msg = secured_sock.recv(1024).decode('UTF-8')
                    if rcvd_msg == MessageType.CERTIFICATE_VERIFIED.name:
                      print(rcvd_msg)
                      try:
                        start_chat(secured_sock)
                        #print(secured_sock.recv(4096).decode('UTF-8'))
                      except:
                        pass
                    else: 
                      print(rcvd_msg)
                      print('client certificate verification failed....terminating connection')
                      secured_sock.close()
                 
                 else: 
                    secured_sock.send(MessageType.CERTIFICATE_VERIFICATION_FAILED.name.encode('UTF-8'))
                    print('server certificate verification failed....terminating connection')
        
        #If TLS is not supported            
        elif rcvd_msg == MessageType.CHAT_STARTTLS_NOT_SUPPORTED.name:
            print('connection unsecure')
            start_chat(socket_obj)              
                  
    else: 
        print('connection failed')
        socket_obj.close()


    socket_obj.close()
    
def certificate_verify(cert, trust_store):
  try:
    
    #load the certificate 'cert' into type ASN1 and creates a object of X.509 store context that will be used to verify certificate
    certificate_ctx = crypto.X509StoreContext(trust_store, crypto.load_certificate(crypto.FILETYPE_ASN1, cert))
    
    #Verify a certificate in a context.
    certificate_ctx.verify_certificate()
    
    return True
  
  except Exception as e:
    print(e)
    return False


#pre loading the root certificate
def create_trust_store(root_cert):
    
  #return an object of X.509 store, that is used to describe a context in which to verify a certificate.   
  trust_store = crypto.X509Store()
  
  with open(root_cert,'r') as cert_file: 
        cert_file_content = cert_file.read()
        
  #Adds root certificate to trust store.
  trust_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert_file_content))
  return trust_store


def start_chat(secured_conn):
  try: 
    #declare two thread objects and call the constructor
    send_msg_thread = threading.Thread(target=send_chat_messages, args = (secured_conn,), daemon=True)
    recv_msg_thread = threading.Thread(target=recv_chat_messages, args = (secured_conn,), daemon=True) 
    
    #start thread which in turn invokes send_chat_messages and recv_chat_messages functions respectively
    send_msg_thread.start()
    recv_msg_thread.start()
    
    #send and recieve thread will run until terminated by timeout or CHAT_CLOSE message.
    send_msg_thread.join()
    recv_msg_thread.join()
  except KeyboardInterrupt:
    pass
  
    
def send_chat_messages(secured_conn):
  while True:
    s_msg = input()
    secured_conn.send(s_msg.encode('UTF_8'))
    
    if s_msg == MessageType.CHAT_CLOSE.name : 
      print("chat terminated \n")
      thread_exit.set()
      secured_conn.close()
      return

def recv_chat_messages(secured_conn):
  global Process_list
  while True:
    #wait for message from client for 1 second else return
    if thread_exit.is_set():
        print('receiver thread exited...')
        return

    r_msg = secured_conn.recv(1024).decode('UTF-8')
    if r_msg == MessageType.CHAT_CLOSE.name:
        print('Chat terminated.. \n')
        secured_conn.close()
        #_thread.interrupt_main()
        os.kill(os.getpid(), signal.SIGINT)
        sys.exit()
     
    print("rcvd message : " + r_msg)       


def main():
    if (len(argv) == 2 and argv[1] == "-s"):
        server()
    elif(len(argv) == 3 and argv[1] == "-c"):
        client(argv[2])
try:
    main()
except Exception:
    pass
