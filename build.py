import subprocess
import argparse
import socket

# Source and output files
SOURCE_FILE = "mem_tracer.c"
OUTPUT_FILE = "mem_tracer.so"

# Compiler flags
CFLAGS = ["-shared", "-fPIC", "-ldl", "-lpthread"]

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def build(compiler, receiver_ip):
    """Compiles the mem_tracer.c file into a shared library."""
    cflags = CFLAGS + [f'-DRECEIVER_IP="{receiver_ip}"' ]
    command = [compiler] + cflags + ["-o", OUTPUT_FILE, SOURCE_FILE]
    print(f"Running command: {' '.join(command)}")
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print("Build successful!")
    except subprocess.CalledProcessError as e:
        print("Build failed!")
        print(f"Return code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the mem_tracer shared library.")
    parser.add_argument("-c", "--compiler", required=True,
                        help="Path to the compiler.")
    parser.add_argument("-r", "--receiver", default=get_local_ip(),
                        help="IP address of the receiver. Defaults to the host's IP.")
    args = parser.parse_args()
    build(args.compiler, args.receiver)
