'''
1. Одержувач отримує дані від відправника.
2. Дані декодуються BASE64.
3. Декодовані дані поділяються на зашифрований одноразовий ключ повідомлення та зашифровані архівовані дані.
4. Зашифрований одноразовий ключ повідомлення розшифровується за допомогою RSA за допомогою приватного ключа отримувача.
5. Зашифровані архівовані дані розшифровуються за допомогою AES за допомогою одноразового ключа повідомлення.
6. Архівовані дані розархівуються та розбиваються на зашифроване хешоване значення MD5 і вихідний текст повідомлення.
7. Зашифроване хешоване значення MD5 розшифровується за допомогою RSA за допомогою приватного ключа отримувача.
8. Вихідне повідомлення Звичайний текст хешується за допомогою того самого алгоритму MD5 і порівнюється з хешованим
значенням MD5. Якщо це те саме, протокол PGP був успішним.
'''

# Imports 
import socket
import sys 
import base64 
import traceback
import hashlib 
import zlib
from ast import literal_eval
from Crypto.PublicKey import RSA 
from Crypto.Random import get_random_bytes 
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import MD5



# Ця функція створює приватний і відкритий ключ RSA для клієнта та зберігає їх у файловій системі у форматі PEM.
def RSA_keyGen(): 
	# Генерація закритого та відкритого ключів RSA для клієнта
	key = RSA.generate(2048)

	private_key = key.export_key()
	file_out = open("server_private.pem", "wb")
	file_out.write(private_key)
	file_out.close()

	public_key = key.publickey().export_key()
	file_out = open("server_public.pem","wb")
	file_out.write(public_key)
	file_out.close()
	
	return key 



# Ця функція створює сервер TCP.
def serverConnection(): 
	# зєднання
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	host = "127.0.0.1"
	port = 15000 

	server.bind((host, port))
	server.listen(1)
	
	return server



# Ця функція використовується для друку довжини, типу та вмісту змінної.
def printData(data, dataString): 
	print("\n\n")
	print("\n{} len : {}\n".format(dataString,len(data)))
	print("\n{} type : {}\n".format(dataString,type(data)))
	print("\n{} : \n".format(dataString))
	print(data)



# Генерація приватних і відкритих ключів RSA для сервера
key = RSA_keyGen() 
# зєднання сервера
server = serverConnection()

# очікування client
while True: 
	print("Waiting for a connection...")
	try: 
		connection, client_address = server.accept() # Connection accepted 
		while True: 
			print("Client connected : " , str(client_address))

			# Отримувати дані від клієнта в 'dataFromClient'
			dataFromClient = connection.recv(3096).decode() 
			dataFromClient_str = "dataFromClient"
			printData(dataFromClient, dataFromClient_str)

			# Налаштування шифрування RSA
			cipher_RSA = PKCS1_OAEP.new(key)

			# Кодування даних в 'data_bytes'
			data_bytes = dataFromClient.encode("ascii") # data_bytes = base64_bytes
			data_bytes_str = "data_bytes_str"
			printData(data_bytes, data_bytes_str)

			# Декодування даних за допомогою декодування Base 64 у 'concat_data_v2_bytes'
			concat_data_v2_bytes = base64.b64decode(data_bytes)
			concat_data_v2_bytes_str = "concat_data_v2_bytes" 
			printData(concat_data_v2_bytes, concat_data_v2_bytes_str)

			# Декодування об'єднаних даних в 'concat_data_v2'
			concat_data_v2 = concat_data_v2_bytes.decode("ascii")
			concat_data_v2_str = "concat_data_v2"
			printData(concat_data_v2, concat_data_v2_str)

			# Розділяємо об'єднані дані в список в 'concat_data_v2_list'
			concat_data_v2_list = concat_data_v2.split("!!!")
			concat_data_v2_list_str = "concat_data_v2_list"
			printData(concat_data_v2_list, concat_data_v2_list_str)

			# Отримуємо зашифровані архівовані дані в 'ciphertext_string'
			ciphertext_string = concat_data_v2_list[0]
			ciphertext_string_str = "ciphertext_string"
			printData(ciphertext_string, ciphertext_string_str)
			
			ciphertext = literal_eval(ciphertext_string)
			ciphertext_str = "ciphertext"
			printData(ciphertext, ciphertext_str)

			# Отримуємо зашифрований ключ сеансу в 'enc_session_key_string'
			enc_session_key_string = concat_data_v2_list[1]
			enc_session_key_string_str = "enc_session_key_string"
			printData(enc_session_key_string, enc_session_key_string_str)
			

			enc_session_key = literal_eval(enc_session_key_string)
			enc_session_key_str = "enc_session_key"
			printData(enc_session_key, enc_session_key_str)

			# Беремо значення nonce у 'nonce_string'
			nonce_string = concat_data_v2_list[2]
			nonce_string_str = "nonce_string"
			printData(nonce_string, nonce_string_str)			
			
			nonce = literal_eval(nonce_string)
			nonce_str = "nonce"
			printData(nonce, nonce_str)

			# Зашифрований ключ сеансу розшифровується за допомогою RSA за допомогою приватного ключа сервера в 'session_key'
			session_key = cipher_RSA.decrypt(enc_session_key)
			session_key_str = "session_key"
			printData(session_key, session_key_str)

			# Налаштування шифрування AES
			cipher_AES = AES.new(session_key, AES.MODE_EAX, nonce)

			# Розшифруйте зашифровані архівовані дані за допомогою RSA за допомогою ключа сеансу в 'zip_data'
			zip_data = cipher_AES.decrypt(ciphertext)
			zip_data_str = "zip_data"
			printData(zip_data, zip_data_str)

			# Розпаковуємо архівовані дані в 'concat_data_bytes'
			concat_data_bytes = zlib.decompress(zip_data) 
			concat_data_bytes_str = "concat_data_bytes"
			printData(concat_data_bytes, concat_data_bytes_str)

			# Декодуємо об'єднані дані в 'concat_data'
			concat_data = concat_data_bytes.decode("ascii") 
			concat_data_str = "concat_data"
			printData(concat_data, concat_data_str)

			# Розділяємо об'єднані дані в список у 'concat_data_list'
			concat_data_list = concat_data.split("!!!")
			concat_data_list_str = "concat_data_list"
			printData(concat_data_list, concat_data_list_str)

			# Звичайний текст в 'plain_text'
			plain_text = concat_data_list[1] 
			plain_text_str = "plain_text" 
			printData(plain_text, plain_text_str)

			# Хешоване повідомлення 'data_RSA_text'
			data_RSA_text = concat_data_list[0]
			data_RSA_text_str = "data_RSA_text"
			printData(data_RSA_text, data_RSA_text_str)
			
			data_RSA = literal_eval(data_RSA_text)
			data_RSA_str = "data_RSA"
			printData(data_RSA, data_RSA_str)

			# Розшифровка зашифрованого хешованого значення за допомогою RSA за допомогою відкритого ключа сервера
			data_md5_bytes = cipher_RSA.decrypt(data_RSA)
			data_md5_bytes_str = "data_md5_bytes"
			printData(data_md5_bytes, data_md5_bytes_str)

			# Кодування відкритого тексту для подальшого використання в 'plain_text_bytes'
			plain_text_bytes = plain_text.encode("ascii")
			plain_text_bytes_str = "plain_text_bytes" 
			printData(plain_text_bytes, plain_text_bytes)

			# Хеш-повідомлення з MD5
			plaintext_md5 = hashlib.md5(plain_text_bytes) 
			plaintext_md5_bytes = plaintext_md5.digest()
			plaintext_md5_bytes_str = "plaintext_md5_bytes"
			printData(plaintext_md5_bytes, plaintext_md5_bytes_str)

			# Порівнюємо отримане хешоване значення та отриманий звичайний хешований текст за тим же алгоритмом
			if data_md5_bytes == plaintext_md5_bytes:

				 print(" PGP OPERATION SUCCESFUL ! ")
				 print(" Client has sent the message : \n")
				 print(plain_text)
			
			elif dataFromClient == "Exit": 
				break 
			else:
				print(" PGP OPERATION FAILED ! ") 
				continue 
	except: 
		traceback.print_exc() 


