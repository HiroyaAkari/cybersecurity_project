import socket 
import threading 
import sys

#setting

TIMEOUT = 1 #second for it to give up on a closig port 
MAX_THREADS = 100 

#globals

open_ports = [] # use as a container for port that we scan
lock = threading.Lock()

#function 

def scan_port(target, port):

    try:

        #to create a new socket (AF_INET = ipv4, sock_stream = TCP )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #set how long we want it to wait before scanning a new one

        s.settimeout(TIMEOUT)

        #try to connect 

        result = s.connect_ex((target, port))

        if result == 0:
            try: 
                service = socket.getservbyport(port)
            except:
                service = "unknown"

            with lock: 
                open_ports.append((port, service))
                print(f" open port {port:5d} -> {service}")

        s.close()

    except socket.gaierror:
        pass

def run_scanner(target, start_port, end_port):

    print(f"[*] starting scanning on port: {target}")
    print(f"[*] port range: {start_port}")
    print(f"[*] timeout per port: {TIMEOUT}S")
    print("-" * 45)

    thread = []

    for port in range(start_port, end_port):
        t = threading.Thread(target=scan_port, args= (target, port))
        thread.append(t)
        t.start()

        if len(thread) >= MAX_THREADS: 
            for t in thread: 
                t.join()
            thread = []

    for t in thread: 
        t.join()

def show_summury():
    print("-" *45)
    if open_ports: 
        open_ports.sort()
        print(f"[+] found {len(open_ports)} open port")
        print(f" {'Port':<10} {'Service'}")
        print(f" {'---':<10} {'---'}")
        for port, service in open_ports: 
            print(f" {port:<10} {service}")
        else: 
            print("\n[-] no open port found")

if __name__ == "__main__":
    print("-"*45)
    print("   python port scanning:")
    print("= "* 45)

    target = input("\n enter target IP or hostname: ").strip()
    start = int( input("start Port: ").strip())
    end = int( input("End port: ").strip())

    try: 
        ip = socket.gethostbyname(target)
        print(f"\n[*] Resolved {target} -> {ip}")
    except socket.gaierror: 
        print(f"[-] cannot resovle '{target}'. check the host name")
        sys.exit
    
    #run the code 

    run_scanner(target, start,end)
    show_summury()



