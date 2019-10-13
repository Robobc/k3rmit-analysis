"""
    Title:      Kermit Analysis
    Desc:       Based on "Sooty" by Connor Jackson. The SOC Analysts all-in-one CLI tool to automate and speed up workflow.
    Author:     Roberto Catalano
    Version:    0.1
    GitHub URL: 
"""
import whois
from ipwhois import IPWhois
import dns.resolver
import requests, sys,json
import socket

def switchMenu(choice):
    if choice == '1':
        whoisMenu()
    if choice == '2':
        nslookupfunc()
    if choice == '3':
        vtMenu()
    if choice == '0':
        exit()


def whoisSwitch(choice):
    if choice == '1':
        ipwhoisfunc()
    if choice == '2':
        domwhoisfunc()
    if choice == '0':
        mainMenu()

def vtSwitch(choice):
    if choice == '1':
        vtdomfunc()
    if choice == '2':
        vtipfunc()
    if choice == '3':
        vtfilefunc()
    if choice == '0':
        mainMenu()

def mainMenu():
    print('''
    ---------------------------------
             KERMIT ANALYSIS           
    ---------------------------------
    What would you like to do? 
        1: WHOIS  
        2: REVERSE DNS 
        3: Reputation Checker (Virus Total Analysis)
        0: Exit''')
    switchMenu(input())

def whoisMenu():
    print('''
    ---------------------------------
           W H O I S  T O O L S     
    --------------------------------- ")
    What would you like to do? 
        OPTION 1: WHOIS on IP Address
        OPTION 2: WHOIS on Domain Address
        OPTION 0: Return to Main Menu''')
    whoisSwitch(input())


def vtMenu():
    print('''
    -------------------------------------- 
        V I R U S T O T A L  T O O L S         
    -------------------------------------- 
    What would you like to do? ")
        OPTION 1: Domain Address Reputation
        OPTION 2: IP Address Reputation
        OPTION 3: File ( MD5, SHA-1 or SHA-256) Reputation
        OPTION 0: Return to Main Menu''')
    vtSwitch(input())


def domwhoisfunc():

    print('''
    --------------------------------------------------
                    W H O I S Domain Analysis:        
    --------------------------------------------------''')
    
    udomain = input('Insert your domain:')
    rget = requests.get('https://' + udomain)
    print('Web Site Status Code: ')
    print(rget) 
    w=whois.whois(udomain)
    print (w)
    whoisMenu()

def ipwhoisfunc(): 

    print('''
    --------------------------------------------------
                    W H O I S IP Analysis:            
    --------------------------------------------------''')

    uip = input('Insert your IP: ')
    try:
        w = IPWhois(uip)
        w = w.lookup_whois()
        addr = str(w['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n WHO IS REPORT:")
        print("  CIDR:      " + str(w['nets'][0]['cidr']))
        print("  Name:      " + str(w['nets'][0]['name']))
       # print("  Handle:    " + str(w['nets'][0]['handle']))
        print("  Range:     " + str(w['nets'][0]['range']))
        print("  Descr:     " + str(w['nets'][0]['description']))
        print("  Country:   " + str(w['nets'][0]['country']))
        print("  State:     " + str(w['nets'][0]['state']))
        print("  City:      " + str(w['nets'][0]['city']))
        print("  Address:   " + addr)
        print("  Post Code: " + str(w['nets'][0]['postal_code']))
       # print("  Emails:    " + str(w['nets'][0]['emails']))
        print("  Created:   " + str(w['nets'][0]['created']))
        print("  Updated:   " + str(w['nets'][0]['updated']))
    except:
        print(" IP Not Found - Checking Domains")
        ip = re.sub('https://', '', ip)
        ip = re.sub('http://', '', ip)
        try:
            s = socket.gethostbyname(ip)
            print(s)
            whoIsPrint(s)
        except:
            print(' IP or Domain not Found')
    whoisMenu()
     
def nslookupfunc():

    print('''
    --------------------------------------------------
                    R E V E R S E  DNS                
    --------------------------------------------------''')
    
    udomain = input('Insert your domain:')
    rget = requests.get('https://' + udomain)
    if rget.status_code == 200:
        print('Web Site Status Code: '+ str(rget.status_code))
        print('DNS Reverse:')

        answers = dns.resolver.query(udomain, 'MX')
        for rdata in answers:
            print ('Host', rdata.exchange, 'has preference', rdata.preference)
    else: 
        print("Web Site is not available ! - Web site code status:" + str(rget.status_code))
    mainMenu()

def vtdomfunc():
    print('''
    --------------------------------------------------
                 Virus Total Domain Analysis:
    --------------------------------------------------''')
    
    udomain = input('Insert your domain:')
    rget = requests.get('https://' + udomain)
    if rget.status_code == 200:
        try: #EAFP
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': '2dbad77533387da6e6464b3ff7e0aa83bb538e17d9b18b31e5871f9ab8594803', 'domain': udomain}
            response = requests.get(url, params=params)
            result = response.json()
            print('Web Site Status Code: ')
            print(rget) 
            print("\n VirusTotal Report:")
            print("   URL Malicious Reportings: " + str(result['positives']) + "/" + str(result['total']))
            print("   VirusTotal Report Link: " + str(result['permalink']))  # gives URL for report (further info)
        except:
            print(" Not found in database")
    else:
        print("Web Site is not available ! - Web site code status:")
        print(rget) 

    vtMenu()

def vtipfunc():
    print('''
    --------------------------------------------------
                 Virus Total IP Analysis:')
    --------------------------------------------------''')
    
    uip = input('Insert your IP:')
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey':'2dbad77533387da6e6464b3ff7e0aa83bb538e17d9b18b31e5871f9ab8594803','ip':uip}
    response = requests.get(url, params=params)
    pos = 0
    tot = 0
    result = response.json()
    for each in result['detected_urls']:
        tot = tot + 1
        pos = pos + each['positives']

    if tot != 0:
        print("   No of Reportings: " + str(tot))
        print("   Average Score:    " + str(pos / tot))
        print("   VirusTotal Report Link: " + "https://www.virustotal.com/gui/ip-address/" + str(uip))
    else:
        print("   No of Reportings: " + str(tot))
    vtMenu()

def vtfilefunc():
    print('''
    --------------------------------------------------
                 Virus Total FILE Analysis
    --------------------------------------------------''')
    
    ufile = input('Insert your MD5, SHA-1 or SHA-256:')

    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey':'2dbad77533387da6e6464b3ff7e0aa83bb538e17d9b18b31e5871f9ab8594803','resource':ufile}

    # makes json pretty
    def pp_json(json_thing, sort=True, indents=4):
        if type(json_thing) is str:
            print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
        else:
            print(json.dumps(json_thing, sort_keys=sort, indent=indents))
        return None

    response = requests.get(url, params=params)

    # turn the respose into json
    json_response = response.json()

    # make it pretty
    pretty_json = pp_json(json_response)

    print(pretty_json)
    vtMenu()

mainMenu()