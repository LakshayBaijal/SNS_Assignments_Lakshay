# Assignment 4 - Buffer Overflow

- Just use commands one by one of that script in this folder or watch this video.

[Screencast from 2025-04-24 22-36-57.webm](https://github.com/user-attachments/assets/b43728cc-4ad1-4211-93fa-3ddd57720697)

### This code only runs in Ubuntu OS and before running the script ensure these 

- Virtual Environment
  
```bash
python3 -m venv venv
source venv/bin/activate
```
- Essential packages including GCC, GDB, and 32-bit libraries required for this.

```bash
sudo apt update
sudo apt install -y build-essential gdb python3 libc6-dev-i386
```

- Disable ASLR (Address Space Layout Randomization)

```bash
sudo sysctl -w kernel.randomize_va_space=0
```

- Check this link for Report in Tex

https://github.com/LakshayBaijal/SNS_Assignments_Lakshay/blob/main/Assignment_4/SNS_Assignment4_Report.pdf
