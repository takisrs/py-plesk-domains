import requests
from tabulate import tabulate
import ssl
from OpenSSL import SSL
from datetime import datetime, timedelta
#import whois
import platform
import subprocess
import socket
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
from socket import socket, gethostbyname
import sys
import warnings
import argparse, getpass
import csv


class Password(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        if values is None:
            values = getpass.getpass()

        setattr(namespace, self.dest, values)
        

def print_server_info(ip, user, password):
    """
    Fetch and print servers info
    @params:
        ip   - Required  : the ip of the server (Str)
        user - Required  : the administrator username (Str)
        password - Required  : The administrator password (Str)
    """

    try:
        r = requests.get(f'https://{ip}:8443/api/v2/server', auth=(user, password), verify=False)
        if r.status_code != 200:
            raise Exception(f"Invalid response from plesk api. Response code: {r.status_code}")
        data = r.json()
        return print(f"{'='*100}\nServer info: {data['hostname']}, platform: {data['platform']}, panel version: {data['panel_version']} ({data['panel_revision']})\n{'='*100}\n")
    except:
        sys.exit(f"Error occured while trying to get server info")


def get_domains(ip, user, password):
    """
    Fetch the list of domains from server
    @params:
        ip   - Required  : the ip of the server (Str)
        user - Required  : the administrator username (Str)
        password - Required  : The administrator password (Str)
    """

    try:
        r = requests.get(f'https://{ip}:8443/api/v2/domains', auth=(user, password), verify=False)
        if r.status_code != 200:
            raise Exception(f"Invalid response from plesk api. Response code: {r.status_code}")
        response = r.json()

        # keep only the data we want
        domains = list(map(lambda x: {'id': x['id'], 'name': x['name'], 'created': x['created'], 'type': x['hosting_type'], 'root': x['www_root']}, response))

        return domains
    except:
        sys.exit("Error occured while trying to get the domain list")


def get_domain_status(id, ip, user, password):
    """
    get domain status
    @params:
        ip   - Required  : the ip of the server (Str)
        user - Required  : the administrator username (Str)
        password - Required  : The administrator password (Str)
    """

    try:
        r = requests.get(f'https://{ip}:8443/api/v2/domains/{id}/status', auth=(user, password), verify=False)
        if r.status_code != 200:
            raise Exception(f"Invalid response from plesk api. Response code: {r.status_code}")
        data = r.json()
        return data['status']
    except:
        return "Error"

def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return subprocess.call(command) == 0


def get_ip(host):
    """
    Get the ip from a hostname
    @params
        host - Required : the hostname
    """

    try:
        return gethostbyname(host)
    except Exception as e:
        return e


def get_certificate(hostname, port=443):
    """
    Get the certificate of a hostname
    @params
        hostname - Required : the hostname
        port - Optional : the port number to look for. Default value: 443
    """

    try:
        hostname_idna = idna.encode(hostname)
        sock = socket()

        sock.connect((hostname, port))
        # peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()
    except:
        crypto_cert = '-'

    return crypto_cert


def get_issuer(cert):
    """
    Get the issuer of a certificate
    @params
        cert - Required : the certificate namespace
    """

    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None
    except:
        return "-"


def print_progress_bar(iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """

    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()


def colored(str, color="red"):
    """
    Color a string for terminal output
    @params
        str - Required : the string to color
        color - Optional : the color to use. Default value: red. Available options: red, yellow, blue
    """

    colors = {
        "red": "\033[91m",
        "yellow": "\33[33m",
        "blue": "\33[34m",
        "green": "\33[32m"
    }
    end = "\033[0m"
    return f"{colors[color]}{str}{end}"


def get_expiry(cert):
    """
    Get the expiration date of a certificate
    @params
        cert - Required : the certificate namespace
    """

    try:
        return cert.not_valid_after
    except:
        return None


def main():
    """
    Main script function
    """

    try:
        parser = argparse.ArgumentParser(prog='pleskdomains', description='Get the list of domains from a plesk panel with certificate information')

        parser.add_argument('host', type=str, help='server hostname or ip address')
        parser.add_argument('-u', dest='username', type=str, required=True, help='Plesk administrator username')
        parser.add_argument('-p', dest='password', type=str, required=True, action=Password, nargs='?', help='Plesk administrator password')
        parser.add_argument('-s', dest='sort', type=str, default='created', help='Provide a sorting option', choices=['name', 'created', 'type', 'ip', 'expiry_date', 'issuer'])
        parser.add_argument('-f', dest='tablefmt', type=str, default='pretty', help='Provide a formatting option for the table', choices=['plain', 'simple', 'github', 'grid', 'fancy_grid', 'pipe', 'orgtbl', 'jira', 'presto', 'pretty', 'psql', 'rst', 'mediawiki', 'moinmoin', 'youtrack', 'html', 'latex', 'latex_raw', 'latex_booktabs', 'textile'])

        args = parser.parse_args()

        host = args.host
        username = args.username
        password = args.password
        sort = args.sort
        tablefmt = args.tablefmt

        print_server_info(host, username, password)

        domains = get_domains(host, username, password)
        domains_count = len(domains)
        loop = 0

        for i in range(domains_count):
            loop += 1
            domain = domains[i]

            domain['status'] = get_domain_status(domain['id'], host, username, password)
            domain['status'] = colored(domain['status'], "red" if domain['status'] != "active" else "green")

            # get domain ip
            server_ip = get_ip(host)
            domain['ip'] = get_ip(domain['name'])
            domain['ip'] = colored(domain['ip'], "green" if server_ip == domain['ip'] else "red")

            # try:
            #     domain_whois = whois.query(domain['name'])
            #     print(domain_whois.__dict__)
            # except:
            #     print("error")
            

            #print(ping(domain['name']))

            # get ssl
            cert = get_certificate(domain['name'])

            if domain['type'] == 'virtual':
                certificate = get_certificate(domain['name'])
                expiry_date = get_expiry(certificate)

                if expiry_date:
                    now = datetime.utcnow()
                    if expiry_date < now:
                        color = "red"
                    elif now + timedelta(seconds = 60*60*24*30) > expiry_date:
                        color = "yellow"
                    elif now + timedelta(seconds = 60*60*24*30*3) > expiry_date:
                        color = "blue"
                    else:
                        color = "green"
                    domain['expiry_date'] = colored(expiry_date, color)
                else:
                    domain['expiry_date'] = '-'

                domain['issuer'] = get_issuer(certificate)
            else:
                domain['expiry_date'] = "-"
                domain['issuer'] = "-"
            
            domains[i] = domain

            print_progress_bar(loop, domains_count)

        domains = sorted(domains, key = lambda i: i[sort])

        print(tabulate(domains, headers="keys", tablefmt=tablefmt))

        keys = domains[0].keys()
        with open(str(host)+'-domains.csv', 'w', newline='')  as output_file:
            dict_writer = csv.DictWriter(output_file, keys)
            dict_writer.writeheader()
            dict_writer.writerows(domains)

    except Exception as e:
        sys.exit(e)


if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    main()