'''
1. Відправник вводить повідомлення.
2. Повідомлення хешується за допомогою MD5.
3. Хешоване значення MD5 зашифровано за допомогою RSA за допомогою відкритого ключа отримувача.
4. Зашифроване хешоване значення MD5 і вихідне повідомлення об’єднані та заархівовані.
5. Архівовані дані шифруються за допомогою AES за допомогою одноразового ключа повідомлення.
6. Одноразовий ключ повідомлення зашифровано за допомогою RSA за допомогою відкритого ключа отримувача.
7. Зашифрований ключ одноразового повідомлення та зашифровані архівовані дані об’єднані.
8. Кінцеві дані кодуються BASE64 і надсилаються до приймача.
'''

# Imports 
import socket
import hashlib 
import zlib 
import base64 
from Crypto.PublicKey import RSA 
from Crypto.Random import get_random_bytes 
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5  




# Ця функція створює приватний і відкритий ключ RSA для клієнта та зберігає їх у файловій системі у форматі PEM.
def RSA_keyGen(): 
	key = RSA.generate(2048) # RSA Keypair Generation
	private_key = key.export_key() # RSA exporting private key 
	file_out = open("client_private.pem", "wb")
	file_out.write(private_key) # Store private key in PEM format
	file_out.close()

	public_key = key.publickey().export_key() # RSA exporting public key 
	file_out = open("client_public.pem","wb") 
	file_out.write(public_key) # Store public key in PEM format
	file_out.close()
	
	# Print Key Values
	print(private_key)
	print(public_key)
	
	return key # Return Key Object



# Ця функція створює TCP-з’єднання з хост-сервером за допомогою сокета.
def clientConnection(): 
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP socket

	host = "127.0.0.1" 
	port = 15000

	client.connect((host, port)) # Client connection 
	
	return client # Return Client object



# Ця функція використовується для друку довжини, типу та вмісту змінної.
def printData(data, dataString): 
	print("\n\n")
	print("\n{} len : {}\n".format(dataString,len(data)))
	print("\n{} type : {}\n".format(dataString,type(data)))
	print("\n{} : \n".format(dataString))
	print(data)



# Ця функція використовується для друку типу, розміру та вмісту в hex хеш-значенні.
def printHash(data_md5): 
	print(data_md5.name)
	print(data_md5.digest_size)
	print(data_md5.hexdigest())



# Генерація закритого та відкритого ключів RSA для клієнта
key = RSA_keyGen() 
# Зєднання
client = clientConnection()



while True: 
	# Message input P 
	message = input("Send message : ")
	
	# Encode message in 'data'
	data = message.encode("ascii")  
	data_str = "data"
	printData(data, data_str)
	
	# Hash message with MD5 in 'data_md5'
	data_md5 = hashlib.md5(data)
	data_md5_str = "data_md5_str"
	printHash(data_md5)
	
	# Encode hash value of the message in 'data_md5_bytes'
	data_md5_bytes = data_md5.digest()
	data_md5_bytes_str = "data_md5_bytes"
	printData(data_md5_bytes, data_md5_bytes_str)  
	
	# RSA Encryption Setup and Read Server's Public Key from file
	server_publicKey = RSA.import_key(open("server_public.pem").read())
	cipher_RSA = PKCS1_OAEP.new(server_publicKey)
	
	# Encrypt the hash value with Server's Public RSA Key in 'data_RSA'
	data_RSA = cipher_RSA.encrypt(data_md5_bytes)
	data_RSA_str = "data_RSA"
	printData(data_RSA, data_RSA_str) 

	# String conversion of Encrypted hash value into 'data_RSA_text'
	data_RSA_text = str(data_RSA)
	data_RSA_text_str = "data_RSA_text"
	printData(data_RSA_text, data_RSA_text_str) 

	# Concatenation of message P and the signed hash of P in 'concat_data'  
	concat_data = data_RSA_text + "!!!" + data.decode("ascii")
	concat_data_str = "concat_data"  
	printData(concat_data, concat_data_str)  

	# Encode Concatenated message in 'concat_data_bytes'  
	concat_data_bytes = concat_data.encode("ascii")
	concat_data_bytes_str = "concat_data_bytes"
	printData(concat_data_bytes, concat_data_bytes_str) 

	# Comress Concatenated message with ZIP format in 'zip_data' 
	zip_data = zlib.compress(concat_data_bytes)
	zip_data_str = "zip_data"
	printData(zip_data, zip_data_str) 
	
	# Create a one-time session key in 'session_key' 
	session_key = get_random_bytes(16)
	session_key_str = "session_key"
	printData(session_key, session_key_str) 
	
	# Encrypt the session key with Server's Public RSA Key in 'enc_session_key' 
	enc_session_key = cipher_RSA.encrypt(session_key)
	enc_session_key_str = "enc_session_key"
	printData(enc_session_key, enc_session_key_str) 
	
	# AES Encryption Setup 
	cipher_AES = AES.new(session_key, AES.MODE_EAX)
	
	# Encrpyt the zipped data with Server's Public RSA Key in 'ciphertext'
	ciphertext = cipher_AES.encrypt(zip_data)
	ciphertext_str = "ciphertext"
	printData(ciphertext, ciphertext_str) 
	
	# Nonce value of AES Encryption - one time value - in 'nonce' 
	nonce = cipher_AES.nonce 
	nonce_str = "nonce"
	printData(nonce, nonce_str) 
	
	# Concatenation of Encrypted zipped data, Encrypted session key and nonce value of AES Encryption in 'concat_data_v2'  
	concat_data_v2 = str(ciphertext) + "!!!" + str(enc_session_key) + "!!!" + str(nonce)
	concat_data_v2_str = "concat_data_v2"
	printData(concat_data_v2, concat_data_v2_str) 

	# Encode New Concatenated message in 'concat_data_v2_bytes' 
	concat_data_v2_bytes = concat_data_v2.encode("ascii")
	concat_data_v2_bytes_str = "concat_data_v2_bytes"
	printData(concat_data_v2_bytes, concat_data_v2_bytes_str) 

	# Encode New Concatenated message with Base 64 Encoding in 'base64_bytes'
	base64_bytes = base64.b64encode(concat_data_v2_bytes)
	base64_bytes_str = "base64_bytes"
	printData(base64_bytes, base64_bytes_str)
	
	# Send the final message to Server
	client.send(base64_bytes) 
	
	print("\nPGP On Sender Side is Done.\n")
	### PGP On Sender Side is Done ### 
	
	if message == "Exit":
		break

client.close()
	
