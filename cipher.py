import re, shlex
import argparse
import requests
from colorama import Fore, Style, init
from subprocess import run

def check_cipher_security(cipher_name):
    url = f"https://ciphersuite.info/api/cs/{cipher_name}/" #API fetch info
    response = requests.get(url)
    
    if response.status_code == 200:
        cipher_data = response.json()
        if cipher_name in cipher_data:
            security_status = cipher_data[cipher_name].get('security', 'unknown')
            return f"{cipher_name} --> {security_status.capitalize()}"
        else:
            return "Cipher suite information not found"
    else:
        return "Error fetching data"
    

parser = argparse.ArgumentParser()
parser.add_argument("url", help="URL of target.")
parser.add_argument("-p", "--port", help="Target port.")
args = parser.parse_args()

url = shlex.quote(args.url)
cipher_checker = "cipher-checker/CipherCheker.py"
default_port = 443

accepted_statuses = ["secure", "recommended"]
color_map = {
        'weak': Fore.YELLOW,
        'insecure': Fore.RED,
        'recommended': Fore.BLUE,
        'secure': Fore.GREEN
    }

if args.port:
    default_port = args.port

def program():
    sslyze = run(["sslyze", f"{url}"], capture_output=True)
    result = re.findall("(TLS 1.*|TLS_.*|SSL .*)", sslyze.stdout.decode())
    struct = {}
    last_head = ""
    for head in result:
        if head[:5] == "TLS 1" or head[:3] == "SSL":
            struct[head] = []
            last_head = head
        elif head[:4] == "TLS_" and not last_head == "" and not "}" in head:
            struct[last_head].append(head.split("  ")[0])

    #res = {l.split("  ")[0] for l in result}
    #print(struct)

    for key, val in struct.items():
        if len(val) < 1:
            print(f"{key} {Fore.GREEN}OK{Style.RESET_ALL}")
        else:
            ciphers = []
            status = True
            for cipher in val:
                current_cipher = check_cipher_security(cipher).strip()
                ciphers.append(current_cipher)
                if not current_cipher.split(" ")[-1].lower() in accepted_statuses:
                    status = False
            if not status:
                print(f"{key} {Fore.RED}NON-COMPLIANCE{Style.RESET_ALL}")
            else:
                print(f"{key} {Fore.GREEN}OK{Style.RESET_ALL}")
            for c in ciphers:
                cname = " ".join(c.split(" ")[:-1])
                res = c.split(" ")[-1]
                status_color = color_map.get(res.lower(), Fore.WHITE)
                print(f"{cname} {status_color}{res}{Style.RESET_ALL}")
        print()

if __name__ == "__main__":
    init()
    program()
#print(struct)