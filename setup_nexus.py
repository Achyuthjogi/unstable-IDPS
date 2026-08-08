import os
import sys
import platform
import subprocess
import stat

def print_step(step):
    print(f"\n[+] {step}")

def run_command(cmd, cwd=None):
    try:
        subprocess.run(cmd, shell=True, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running command: {cmd}")
        sys.exit(1)

def main():
    print("="*50)
    print("   Nexus IDPS Cross-Platform Setup Installer")
    print("="*50)
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    frontend_dir = os.path.join(root_dir, "frontend")
    os_name = platform.system()
    
    print_step("Installing Python Dependencies...")
    pip_cmd = "pip" if os_name == "Windows" else "pip3"
    run_command(f"{pip_cmd} install -r requirements.txt", cwd=backend_dir)
    
    print_step("Installing Node Dependencies...")
    npm_cmd = "npm.cmd" if os_name == "Windows" else "npm"
    run_command(f"{npm_cmd} install", cwd=frontend_dir)
    
    print_step("Creating Global Executable...")
    bin_name = "nexus-idps"
    
    if os_name in ["Linux", "Darwin"]:
        # Bash script for Unix-like systems
        script = f"""#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (e.g., sudo {bin_name})"
  exit
fi

cd "{root_dir}"
echo "[*] Starting Nexus IDPS Backend..."
cd backend
python3 main.py &
BACKEND_PID=$!

cd ../frontend
echo "[*] Starting Nexus IDPS Frontend..."
npm run dev &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID; exit" SIGINT SIGTERM
wait
"""
        bin_path = f"/usr/local/bin/{bin_name}"
        try:
            with open(bin_path, "w") as f:
                f.write(script)
            os.chmod(bin_path, os.stat(bin_path).st_mode | stat.S_IEXEC)
            print_step(f"Success! Created global command: {bin_path}")
            print(f"\nYou can now start the tool from anywhere by typing: sudo {bin_name}")
        except PermissionError:
            print("\n[-] Permission denied to write to /usr/local/bin.")
            print("Please run this setup script with sudo: sudo python3 setup_nexus.py")
            sys.exit(1)
            
    elif os_name == "Windows":
        # Batch script for Windows
        script = f"""@echo off
:: Request Admin Privileges check here (manual for now)
cd /d "{root_dir}"

echo [*] Starting Nexus IDPS Backend...
start "Nexus Backend" cmd /k "cd backend && python main.py"

echo [*] Starting Nexus IDPS Frontend...
start "Nexus Frontend" cmd /k "cd frontend && npm run dev"

echo Nexus IDPS is running. Close the new windows to stop.
"""
        bat_path = os.path.join(root_dir, f"{bin_name}.bat")
        with open(bat_path, "w") as f:
            f.write(script)
            
        print_step(f"Success! Created {bat_path}")
        print("\nTo make it globally available:")
        print(f"1. Move {bin_name}.bat to a directory in your system PATH (e.g., C:\\Windows\\System32)")
        print(f"2. Run it from an Administrator command prompt by typing: {bin_name}")

if __name__ == "__main__":
    main()
