# Network packet collector

Network packet collector is a cross-platform tool to collect network packets that are sent and received by operating system's processes.

The tool collects UDP and TCP sessions on network interfaces and determines what operating system processes they belongs to. If the process is in a list then the network packet collector dumps a limited set of packets of the session to a pcap file. A session is determined by 5-tuple.

The network packet collector uploads saved pcap files to a server.

This tool can be run on Linux, Mac and Windows platforms as follows:

1. The user runs it as root/administrator, providing a comma-separated list of processes they are interested in in .env file or as an environment variable. The full list of environment variables that can be used to adjust configuration is available in the session_collector.py file in SessionCollectorConfig class' documentation strings.
2. The user then uses the computer as usual, and the script captures all specified traffic into packet capture files, accociating sessions with processes, and ignoring all sessions that are not related to any process in PROCESS_LIST.
3. The resulting packet captures are labeled sessions that can now be used to train ML models for traffic-analysis.

The project was developed and tested on python 3.13.2 and python 3.8.10.

## How to install dependencies and run the script

### Unix (Linux/MacOS)

In order to set up a python environment with all the necessary dependencies,
run the following:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo $(which python3) main.py # you can list interfaces with ip link show
```

Alternatively, if you have nix installed, run

```bash
nix --extra-experimental-features "nix-command flakes" develop
sudo $(which python3) main.py # you can list interfaces with ip link show
```

### Windows

First of all, make sure that you have python 3.8 or later installed and
added to PATH. Next, run cmd as administrator and cd into the project directory.
Then run:

```bash
pip install -r requirements.txt
set PROCESS_LIST=...
set ...
python main.py
```

## How to pack the script into a standalone binary

In order to pack the script, you need to package on the same OS and architecture you're packaging for. WINE and VMs should work for this, if necessary. Use scripts in deploy/ directory from inside the directory. After running them, the binary should appear in dist/ directory.

For linux, you need to have docker installed. For Windows and MacOS, you need to have python 3.13 and wireshark installed.

Before each build, remove .spec files, dist/ directory and build directory.

### notes

Make sure that the warnings list at `build/main/warn-main.txt` does not contain
any of the core packages from requirements.txt. Otherwise, you may have problems
with your build environment.

# Instruction for Game Packet Collection (for Windows)

Purpose:
Collect correct network recordings of game sessions for further analysis.

1. Tools Installing/Configuring

- Install this packet capturing library <https://npcap.com/dist/npcap-1.87.exe>
- Copy a compiled utility ([https://github.com/InangoSystems/network-packet-collector/releases/download/v0.1/session-collector-windows-x86_64.exe)](https://github.com/InangoSystems/network-packet-collector/releases/download/v0.1/session-collector-windows-x86_64.exe) to any folder you wish 
- Copy session-collector.cfg (<https://github.com/InangoSystems/network-packet-collector/blob/main/session-collector.cfg>) into the same folder
- Add into session-collector.cfg (INTERFACE_LIST section) the Windows name of the interface used for your activity (e.g. Realtek PCIe GbE Family Controller, you may discover it using ipconfig /all via Windows command line)
- Add into session-collector.cfg (PROCESS_LIST section) the process names for your gameplay

For example:
Valorant - valorant,riotclientservices,vanguardtray,vgtray,vgservice,vgk
CS2 - cs2,steam,steamservice,gameoverlayui,steamwebhelper
Apex Legends - r5apex,steam,steamservice,gameoverlayui,steamwebhelper,easyanticheat
Fortnite - fortniteclient,fortniteclient-win64-shipping,epicgameslauncher,epicwebhelper,easyanticheat
Call of Duty - cod,codlauncher,codship,battle,battlenet,blizzardagent
Overwatch 2 - overwatch,overwatchlauncher,battle,battlenet,blizzardagent
League of Legends - leagueclient,leagueclientux,leagueclientuxrender,lolclient,riotclientservices
Dota 2 - dota2,dota2launcher,steam,steamservice,gameoverlayui,steamwebhelper
Rainbow Six Siege - rainbow6,ubisoftconnect,upc,easyanticheat
Destiny 2 - destiny2,steam,steamservice,gameoverlayui,steamwebhelper,battleye
Rocket League - rocketleague,steam,steamservice,gameoverlayui,steamwebhelper,epicgameslauncher

These are online multiplayer games that are highly dependent on internet latency and stability. If you may suggest other games then feel free to ask. At this time, we are not interested in online games that are less dependent on latency (e.g. Minecraft, Among Us).

The application is console-based and requires admin privileges. Just start it and leave console opened or minimized. No other configuration is needed. The application will collect pcaps and automatically upload them to our server.

You can request a process list for your game from any AI chat using:
Provide the Windows process list for <Quake2> as a comma-separated string - no .exe, no spaces.

1. Start session-collector-windows-x86_64.exe by right-click on it and select "Run as administrator".
2. The Windows command line window will appear and the utility output as well.
3. All gathered data will be stored in the PCAPS sub-folder, and it will be cleared after each data sending session (the interval can be adjusted via session-collector.cfg).

Thank you for your help and cooperation.
Please feel free to contact us via support@inango-systems.com.
