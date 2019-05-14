import ssl
import sys
import click
import socket
import logging
import OpenSSL
import datetime
import certstream
from fuzzywuzzy import fuzz

socket.setdefaulttimeout(2)

scan = {}
flag = {}

def combine(info):
    res = {}
    for k,v in info:
        if not res.get(k):
            res[k.decode("utf-8")] = v.decode("utf-8")
    return res

def similar(message, context):
    if message['message_type'] == "heartbeat":
        return
    if message['message_type'] == "certificate_update":

        for item in message['data']['chain']:
            if fuzz.token_sort_ratio(item['subject']['O'],scan['subject']['O']) >= 50 or item['serial_number'] == scan['serial_number']:
                sys.stdout.write(u"[{}] {} (SAN: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), message['data']['leaf_cert']['all_domains'][0], ", ".join(message['data']['leaf_cert']['all_domains'][1:])))

            # if not flag.get(item['subject']['O']):
            #     flag[item['subject']['O']] = item['serial_number']
            #     sys.stdout.write(u"[{}] {} (Serial Number: {})\n".format(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S'), item['subject']['O'], item['serial_number']))
            
            sys.stdout.flush()

@click.command()
@click.option('--hostname',"-h" ,prompt='Your hostname',help='The target host you want to greet.')
def find(hostname):
    port = 443
    cert = ssl.get_server_certificate((hostname, port), ssl_version=ssl.PROTOCOL_TLSv1)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

    rootCA = x509.get_issuer().get_components()
    subject = x509.get_subject().get_components()

    scan['signature'] = x509.get_signature_algorithm().decode("utf-8")
    scan['serial_number'] = x509.get_serial_number()
    scan['subject'] = combine(subject)
    scan['rootCA'] = combine(rootCA)

    print("\n----------------\n{}\n{}\n{}\n----------------\n\n".format(hostname,scan['subject']['O'],scan['serial_number']))

    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(similar, url='wss://certstream.calidog.io/')

if __name__ == "__main__":
    try:
        find()
    except Exception as e:
        print("\n----------------------------------------------------------------\nI'm afraid we got a problem, and script would exit immediately. \nplease check again \n----------------------------------------------------------------\n")
