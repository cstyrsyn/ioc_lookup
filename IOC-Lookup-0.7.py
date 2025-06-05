#Requires Win11 or *nux
#overall todo: Add better error handling
import requests
import json
import argparse
import datetime
import os
from datetime import datetime as dt, timedelta
from colorama import Fore, Style
import countrycode


#Set Global Vars
global_ip= ''
global_url= ''
global_hash= ''
global_email= ''
abipdbkey = ''
vtkey = ''
ipqskey = ''
shodankey = ''
maxage= 30

#SETUP FUNCTIONS

def getargs():
    global global_ip
    global global_url
    global global_hash
    global global_email
    global maxage
    parser=argparse.ArgumentParser(description='IOC Lookup Tool')
    parser.add_argument('-ip','--ip', default='skip')
    parser.add_argument('-url','--url', default='skip')
    parser.add_argument('-hash', default='skip')
    parser.add_argument('-email', default='skip')
    parser.add_argument('-lookback',default=30)
    args=parser.parse_args()
    global_ip = args.ip
    global_url = args.url
    global_hash = args.hash
    global_email = args.email
    maxage = args.lookback

def grabkeys():
    global abipdbkey
    global vtkey
    global ipqskey
    global shodankey

    try:
        abipdbkey = os.environ['abdb_key']
        vtkey = os.environ['vt_key']
        ipqskey = os.environ['ipqs_key']
        shodankey = os.environ['shodan_key']
    except:
        print("Keys not present, have you ran add-api.ps1?")

#UTILITY FUNCTIONS
def titleprint(title):
    print("-- {} --".format(title))

def convertepoch(time):
    dt = str(datetime.datetime.fromtimestamp(time))
    return dt

def link(uri, label=None):
    if label is None: 
        label = uri
    parameters = ''

    # OSC 8 ; params ; URI ST <name> OSC 8 ;; ST 
    escape_mask = '\033]8;{};{}\033\\{}\033]8;;\033\\'

    return escape_mask.format(parameters, uri, label)

#Colouring

def col_text(text):
    col = ''
    if text == 'False' or text == 'high':
        col = Fore.GREEN + text + Style.RESET_ALL
    if text == 'True' or text == 'low' or text == 'malicious':
        col = Fore.RED + text + Style.RESET_ALL
    return col

def col_text_inv(text):
    col = ''
    if text == 'True':
        col = Fore.GREEN + text + Style.RESET_ALL
    if text == 'False':
        col = Fore.RED + text + Style.RESET_ALL
    return col

def col_numrange(num):
    if num == 'Unknown':
        return num
    else:
        num = int(num)
        col = ''
        if 70 <= num <= 100:
            col = Fore.GREEN + str(num) + Style.RESET_ALL
        if 40 <= num <= 69:
            col = Fore.YELLOW + str(num) + Style.RESET_ALL
        if 0 <= num <= 39:
            col = Fore.RED + str(num) + Style.RESET_ALL
        return col
    
def col_numrange_inv(num):
    if num == 'Unknown':
        return num
    else:
        num = int(num)
        col = ''
        if 70 <= num <= 100:
            col = Fore.RED + str(num) + Style.RESET_ALL
        if 40 <= num <= 69:
            col = Fore.YELLOW + str(num) + Style.RESET_ALL
        if 0 <= num <= 39:
            col = Fore.GREEN + str(num) + Style.RESET_ALL
        return col
def col_rep(num):
    num = int(num)
    col = ''
    if num < 0:
        col = Fore.RED + str(num) + Style.RESET_ALL
    else:
        col = Fore.GREEN + str(num) + Style.RESET_ALL
    return col

def col(col,text):
    text = str(text)
    if col == 'red':
        return Fore.RED + text + Style.RESET_ALL
    if col == 'yel':
        return Fore.YELLOW + text + Style.RESET_ALL
    if col == 'grn':
        return Fore.GREEN + text + Style.RESET_ALL
    
def col_date(date):
    days = 7
    if dt.strptime(date, "%Y-%m-%d %H:%M:%S") + timedelta(days=days) > dt.now():
        return Fore.RED + str(date) + Style.RESET_ALL
    else:
        return date

#IPQS FUNCTIONS

def ipqs_get(item,check):
    #we have a critical mass of ipqs items, makes sense to move the get request to its own function
    url = 'https://www.ipqualityscore.com/api/json/' + item + "/"
    
    
    response = requests.request(method='GET', url=url+ipqskey+"/"+check)
    return json.loads(response.text)

def ipqs(ip):
    #IP Lookup
    #https://www.ipqualityscore.com/documentation/proxy-detection-api/overview

    decodedResponse = ipqs_get('ip',ip)

    print("--IPQS VPN CHECK--")
    success = decodedResponse["success"]
    if success==False:
        if decodedResponse["message"].startswith("You have insufficient credits to make this query."):
            print("Insufficient Credits")
        if decodedResponse["message"].startswith("Invalid IPv4 address, IPv6 address or hostname."):
            print("Invalid IP")
    else:
        print("Location: {} - {} ({}, {})".format(decodedResponse["country_code"],countrycode.lookup(decodedResponse["country_code"]),decodedResponse["region"],
                                             decodedResponse["city"] + ")"))
        print("ISP: {}".format(decodedResponse["ISP"]))
        print("Organisation: {}".format(decodedResponse["organization"]))
        print("VPN: {} [Active: {}]".format(col_text(str(decodedResponse["vpn"])),col_text(str(decodedResponse["active_vpn"]))))
        print("TOR: {} [Active: {}]".format(col_text(str(decodedResponse["tor"])),col_text(str(decodedResponse["active_tor"]))))
        print("Proxy: {}".format(col_text(str(decodedResponse["proxy"]))))
        print("Bot: {}".format(col_text(str(decodedResponse["bot_status"]))))
        print("Fraud Score: {} [Recent Abuse: {}]".format(col_numrange(decodedResponse["fraud_score"]),
                                                          col_text(str(decodedResponse["recent_abuse"]))))
        print()

def ipqs_email(email):
    #email lookup
    #https://www.ipqualityscore.com/documentation/email-validation-api/overview
    
    decodedResponse = ipqs_get('email',email)
        
    print("--IPQS EMAIL CHECK--")
    print(email)
    success = decodedResponse["success"]
    if success==False:
        if decodedResponse["message"].startswith("You have insufficient credits to make this query."):
            print("Insufficient Credits")
        if decodedResponse["message"].startswith("Invalid email address."):
            print("Invalid email")
    else:
        print("First Seen: {}".format(col_date(convertepoch(decodedResponse["first_seen"]["timestamp"]))))
        print("Valid: {}".format(col_text_inv(str(decodedResponse["valid"]))))
        print("First Name: {}".format(decodedResponse["first_name"]))
        print("Deliverability: {} [SMTP Score: {}, Overall Score: {}]".format(col_text(decodedResponse["deliverability"]),
                                                                             decodedResponse["smtp_score"],
                                                                             decodedResponse["overall_score"])) 
        print("Suspect: {} [Recent Abuse: {}, Frequent Complainer: {}, Fraud Score: {}]"
              .format(col_text(str(decodedResponse["suspect"])),col_text(str(decodedResponse["recent_abuse"])),
                      col_text(str(decodedResponse["frequent_complainer"])),col_numrange(decodedResponse["fraud_score"])))
        print("Disposable: {}".format(col_text(str(decodedResponse["disposable"])))) 
        print("Leaked: {}".format(col_text(str(decodedResponse["leaked"]))) )
        print("Suggested Domain: {} [Age: {}]".format(decodedResponse["suggested_domain"],
                                                      convertepoch(decodedResponse["domain_age"]["timestamp"])))
        print()

def ipqs_url(url):
    #url lookup
    #https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview
    
    #url = 'https://www.ipqualityscore.com/api/json/url/' 
    decodedResponse = ipqs_get('url',url)
        
    print("--IPQS URL CHECK--")
    #print(url)
    success = decodedResponse["success"]
    if success==False:
        if decodedResponse["message"].startswith("You have insufficient credits to make this query."):
            print("Insufficient Credits")
        if decodedResponse["message"].startswith("Invalid URL or domain."):
            print("Invalid URL")
    else:
        print("Domain: {} [Root Domain: {}]".format(decodedResponse["domain"], decodedResponse["root_domain"]))
        print("Domain Age: {}".format(col_date(convertepoch(decodedResponse["domain_age"]["timestamp"]))))
        print("Category: {}".format(decodedResponse["category"]))
        print("Page Title: {}".format(decodedResponse["page_title"]))
        try:
            countrycode = countrycode.lookup(decodedResponse["country_code"])
        except:
            countrycode = "n/a"
        print("IP Address: {} [Country: {} - {}]".format(decodedResponse["ip_address"],
                                                    decodedResponse["country_code"],
                                                    countrycode))
        print("Server: {}".format(decodedResponse["server"]))
        print("Domain Rank: {}".format(decodedResponse["domain_rank"]))
        #print("Domain Trust: {}".format(decodedResponse["domain_trust"]))
        print("Unsafe: {}".format(col_text(str(decodedResponse["unsafe"]))))
        print("Suspicious: {} [Risk Score: {}]".format(col_text(str(decodedResponse["suspicious"])),
                                                       col_numrange_inv(decodedResponse["risk_score"])))
        print("Phishing: {}".format(col_text(str(decodedResponse["phishing"]))))
        print("Malware: {}".format(col_text(str(decodedResponse["malware"]))))
        print("Spamming: {}".format(col_text(str(decodedResponse["spamming"]))))
        print("DNS Valid: {}".format(col_text_inv(str(decodedResponse["dns_valid"]))))
        print("  Parking: {}".format(col_text(str(decodedResponse["parking"]))))
        print("  A Records: {}".format(decodedResponse["a_records"]))
        print("  MX Records: {}".format(decodedResponse["mx_records"]))
        print("  NS Records: {}".format(decodedResponse["ns_records"]))
        print("Risky TLD: {}".format(col_text(str(decodedResponse["risky_tld"]))))
        print("Technologies: {}".format(decodedResponse["technologies"]))
        print()
        if decodedResponse["ip_address"] != "N/A":
            while True:
                ip_pivot = "y"
                ip_pivot = input("Check IP address? (Y/N) ")
                if ip_pivot.lower() == "y":
                        print("Report for: " + decodedResponse["ip_address"])
                        print("")
                        iplocation(decodedResponse["ip_address"])
                        ipqs(decodedResponse["ip_address"])
                        abuseipdb(decodedResponse["ip_address"])
                        veetee(decodedResponse["ip_address"],ip_flag=True)
                        break
                if ip_pivot.lower() == "n":
                    print("Skipping")
                    print()
                    break
                else:
                    print("Invalid entry, please select Y or N")

#VIRUSTOTAL FUNCTIONS

def vt_get(url, item, tail=''):
    url = url
    #todo: put request info in and parse results, will come as object so might need different approach, best approach seems to be, 
    # make a selection then have last element be the URL to the full page for all results  
    # https://docs.virustotal.com/reference/ip-info
    headers = {
    'Accept': 'application/json',
    'x-apikey': vtkey
    }
    response = requests.request(method='GET', url=url+item+tail, headers=headers)
      
    return json.loads(response.text)

def vt_names(json):
    print("Detected Filenames: {}".format(json))
    print("")
    
    
def vt_times(json):
        try:
            print("Last Analysis Date: {}".format(convertepoch((json["last_analysis_date"]))))
        except:
            print("Last Analysis Date: Unknown")
        try:
            print("First Seen in the Wild: {}".format(col_date(convertepoch((json["first_seen_itw_date"])))))
        except:
            return 0
        print("")
        
def vt_mitre(hash):
    url = 'https://www.virustotal.com/api/v3/files/'
    tail = '/behaviour_mitre_trees'
    decodedResponse = vt_get(url,hash,tail)
    tac_link = "https://attack.mitre.org/tactics/"
    tech_link = "https://attack.mitre.org/techniques/"

    for key in decodedResponse:
        for keys in decodedResponse["data"]:
            if keys != "None":
                print(keys)
                for tactic in decodedResponse["data"][keys]["tactics"]:
                    #print(decodedResponse["data"][keys]["tactics"][tactic]["id"]) 
                    #print(" {} - {}".format(tactic["id"],tactic["name"]))
                    print(" {}".format(link(tac_link+tactic["id"],tactic["id"] + " - " + tactic["name"])))
                    #print(tactic["techniques"])
                    for tech in tactic["techniques"]:
                        #print("  {} - {}".format(tech["id"],tech["name"]))
                        print("  {}".format(link(tech_link+tech["id"],tech["id"] + " - " + tech["name"])))
  
def vt_counters(json):
        try:
            ct = json["confirmed-timeout"]
        except:
            ct = 0
        try:
            failure = json["failure"]
        except:
            failure = 0
        try:
            undetected = json["undetected"]
        except:
            undetected = 0
        try:
            type_unsup = json["type-unsupported"]
        except:
            type_unsup = 0
            
        harmless = json["harmless"]
        malicious = json["malicious"]
        suspicious = json["suspicious"]
        timeout = json["timeout"]
        
        
        sum = ct + failure + harmless + malicious + suspicious + timeout + type_unsup + undetected
        error = ct + failure + timeout + type_unsup
        print("Malicious: {} / {}".format(col('red',malicious), col('red',sum)))
        print("Suspicious: {} / {}".format(col('yel',suspicious), col('yel',sum)))
        print("Harmless: {} / {}".format(col('grn',harmless), col('grn',sum)))
        print("Undetected: {} / {}".format(undetected, sum))
        print("Error: {} / {}".format(error,sum))
        print("")
        
def vt_sandbox(json):
    
    for key in json.keys():
        #define vars
        mal_names = []
        mal_class = []
        confidence = 0
        #check if data exists
        try:
            mal_names = json[key]["malware_names"]
        except:
            mal_names = "Unknown"
        try:
            mal_class = json[key]["malware_classification"]
        except:
            mal_class = "Unknown"
        try:
            confidence = json[key]["confidence"]
        except:
            confidence = "Unknown"
        
        if json[key]["sandbox_name"] != "None":
            print(json[key]["sandbox_name"])
            print("Malware Names: {}".format(mal_names))
            print("Category: {}, Classification: {}".format(col_text(str(json[key]["category"])), mal_class)) 
            print("Confidence: {}".format(col_numrange(confidence)))
        print("")

def vt_ip(json):
    # https://docs.virustotal.com/reference/ip-info
    try: 
        
        print("Country: {} - {}".format(json["country"],countrycode.lookup(json["country"])))
    except:
        print("Country: Unknown")    
    try: 
        print("AS Owner: {}".format(json["as_owner"]))
    except:
        print("AS Owner: Unknown") 
    try: 
        print("Internet Registry: {}".format(json["regional_internet_registry"]))
    except:
        print("Internet Registry: Unknown")   

    print("Reputation: {}".format(col_rep(json["reputation"])))
    try:
        print("Whois Date: {}".format(convertepoch(json["whois_date"])))
    except:
        print("Whois Date: Unknown")
    print("")
    print("-LAST CERTIFICATE INFO-")
    try:
        print("  Thumbprint: {}".format(json["last_https_certificate"]["thumbprint"]))
        print("  Subject Alternative Names: {}".format(json["last_https_certificate"]
                                                       ["extensions"]["subject_alternative_name"]))
        print("  Validity: {} - {}".format(json["last_https_certificate"]["validity"]["not_before"],
                                           json["last_https_certificate"]["validity"]["not_after"]))
    except:
        print("None")
    print()

def vt_url(json):
    url = 'https://www.virustotal.com/api/v3/domains/'
    #todo: upgrade DNS results to group by record type
    #      upgrade Error handling to have less try/except blocks - could have a field that gets used when a KeyError happens
    # https://docs.virustotal.com/reference/domain-info   
    try:        
        print("Creation: {}".format(col_date(convertepoch(json["creation_date"]))))
    except:
        print("Creation: Unknown")
    try:
        print("Last Update: {}".format(convertepoch(json["last_update_date"])))
    except:
        print("Last Update: Unknown")
    print("Last Modification: {}".format(convertepoch(json["last_modification_date"])))
    print("Reputation: {}".format(col_rep(json["reputation"])))
    try:
        print("Registrar: {}".format(json["registrar"]))
    except:
        print("Registrar: Unknown")
    print("Categories: {}".format(json["categories"]))
    print()
        
    print("-SSL CERT INFO-")
    try:
        print("Last HTTPS Certificate Date: {}".format(convertepoch(json["last_https_certificate_date"])))
        print("Thumbprint: {}".format(json["last_https_certificate"]["thumbprint_sha256"]))
        print("Validity: {} - {}".format(json["last_https_certificate"]["validity"]["not_before"],
                                         json["last_https_certificate"]["validity"]["not_after"]))
        print("Subject Alternative Names: {}".format(json["last_https_certificate"]["extensions"]
                                                     ["subject_alternative_name"]))
        print("Issuer: {} [Country: {}]".format(json["last_https_certificate"]["issuer"]["O"],
                                                json["last_https_certificate"]["issuer"]["C"]))
        print("Alternative Names: {}".format(json["last_https_certificate"]["subject"]))
        print()
    except:
        print("None")
        print()
    print("-DNS RECORDS-")
    try:
        print("Last DNS change: {}".format(convertepoch(json["last_dns_records_date"])))
        print("DNS Records: {}".format(json["last_dns_records"]))
    except:
        print("None")
    print()
    
    
def veetee(item,ip_flag=False,url_flag=False,hash_flag=False):
    
    if ip_flag==True:
        titleprint("VIRUSTOTAL: IP")
        url = 'https://www.virustotal.com/api/v3/ip_addresses/'
        
    if url_flag==True:
        titleprint("VIRUSTOTAL: URL")
        url = 'https://www.virustotal.com/api/v3/domains/'
    if hash_flag==True:
        titleprint("VIRUSTOTAL: FILE")
        url = 'https://www.virustotal.com/api/v3/files/'
        
    
    decodedResponse = vt_get(url,item)
    
    #check for error
    first = list(decodedResponse.keys())[0]
    if first == 'error':
        #print(decodedResponse['error']['code'])
        print(decodedResponse['error']['message'])
    else:
        #print(json.dumps(decodedResponse, sort_keys=True, indent=4))
        
                
        #get X/Y malicious rating
        vt_counters(decodedResponse['data']['attributes']["last_analysis_stats"])
        #get timings
        vt_times(decodedResponse['data']['attributes'])
        
        if hash_flag==True:
        #get names
            vt_names(decodedResponse['data']['attributes']["names"])
            print("-SANDBOX RESULTS-")
            try:
                vt_sandbox(decodedResponse['data']['attributes']["sandbox_verdicts"])
            except:
                print("None")
                print()
            
            print("-MITRE TECHNIQUES-")
            if vt_mitre(item) is None:
                #print("None")
                print()
            else:
                vt_mitre(item)
            
            print("Full Results: https://www.virustotal.com/gui/file/" + item)
            print()
            
        if ip_flag==True:
        #get names
            vt_ip(decodedResponse['data']["attributes"])
 
            print("Full Results: https://www.virustotal.com/gui/ip-address/" + item)
            print()
        
        if url_flag==True:
        #get names
            vt_url(decodedResponse['data']["attributes"])
 
            print("Full Results: https://www.virustotal.com/gui/domain/" + item)
            print()

#OTHER FUNCTIONS

def abuseipdb(ip,maxage=30):
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    querystring = {
    'ipAddress': ip,
    'maxAgeInDays': maxage
    }
    headers = {
    'Accept': 'application/json',
    'Key': abipdbkey
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    titleprint("ABUSEIPDB")
    try: 
        cc = countrycode.lookup(decodedResponse['data']["countryCode"])
    except:
        cc = "Unknown"

    print("Country: {} - {}".format(decodedResponse['data']["countryCode"],cc))
    print("ISP: {}".format(decodedResponse['data']["isp"]))
    print("Usage Type: {}".format(decodedResponse['data']["usageType"]))
    print("Domain: {}".format(decodedResponse['data']["domain"]))
    print("Tor?: {}".format(col_text(str(decodedResponse['data']["isTor"]))))
    print("Whitelisted?: {}".format(decodedResponse['data']["isWhitelisted"]))
    print("Abuse Confidence Score: {}".format(col_numrange(decodedResponse['data']["abuseConfidenceScore"])))
    print("Total Reports: {}".format(decodedResponse['data']["totalReports"]))
    print("Last Reported At: {}".format(decodedResponse['data']["lastReportedAt"]))
    print("")
    
def iplocation(ip):
    #IP Lookup
    #https://api.iplocation.net
    
    url = 'https://api.iplocation.net/?ip='
    
    response = requests.request(method='GET', url=url+ip)
    decodedResponse = json.loads(response.text)
    
    print("--IPLOCATION--")
    print("Country: {} - {}".format(decodedResponse["country_code2"],countrycode.lookup(decodedResponse["country_code2"])))
    print("ISP: {} ".format(decodedResponse["isp"]))
    print()
    
def shodan(item):
    #IP and ? Lookup
    #upgrade this with more capability from Shodan
    #https://developer.shodan.io/api
    
    url = "https://api.shodan.io/shodan/host/"
    querystring = {
        'key': shodankey
        }
    headers = {
        'content-type': 'application/json',
        }
    response = requests.request(method='GET', url=url+item, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    
    print("--SHODAN IP CHECK--")
    
    try:
        print(decodedResponse["error"])
    
    except:
        print("Location: {} - {} (Region: {}, City: {})".format(decodedResponse["country_code"], countrycode.lookup(decodedResponse["country_code"]),
                                                           decodedResponse["region_code"],
                                                           decodedResponse["city"]))
        print("ISP: {}".format(decodedResponse["isp"]))
        print("ASN: {}".format(decodedResponse["asn"]))
        print("Organisation: {}".format(decodedResponse["org"]))
        print("Hostnames: {}".format(decodedResponse["hostnames"]))
        #print("Created: {}".format(decodedResponse["data"]["timestamp"]))
        print("Domains: {}".format(decodedResponse["domains"]))
        print()
        if decodedResponse["ports"]:
            print("Open Ports: {}".format(decodedResponse["ports"]))
        if decodedResponse["tags"]:
            print("Tags: {}".format(decodedResponse["tags"]))
    print()
    
#TO BE DEVELOPED
    
def greynoise():
    url = ''
    #IP Lookup
    #https://www.greynoise.io/features/product-feature-api
            
def echotrail():
    url = ''
    #Process Lookup - see if it is benign
    #paid
    #https://www.echotrail.io/docs/quickstart

def censys():
    url = ''
    #IP and URL lookup
    #paid
    #https://search.censys.io/api/
    
#DEBUG FUNCTIONS

#def vt_full(hash):
#    url = 'https://www.virustotal.com/api/v3/files/'
#    headers = {
#    'Accept': 'application/json',
#    'x-apikey': vt
#    }
#    response = requests.request(method='GET', url=url+hash, headers=headers)
#    decodedResponse = json.loads(response.text)
#    #print(decodedResponse)
#    #check for error
#    titleprint("VIRUSTOTAL: FILE")
#    first = list(decodedResponse.keys())[0]
#    if first == 'error':
#        #print(decodedResponse['error']['code'])
#        print(decodedResponse['error']['message'])
#    else:
#        print(json.dumps(decodedResponse, sort_keys=True, indent=4))

#SETUP
getargs()
grabkeys()

#FUNCTION CALLS

print("---IOC LOOKUP---")
if global_ip != 'skip':
    print("Report for: " + global_ip)
    print("")
    #iplocation(global_ip)
    ipqs(global_ip)
    abuseipdb(global_ip, maxage)
    veetee(global_ip,ip_flag=True)
    #shodan(global_ip)
if global_hash != 'skip':
    print("Report for: " + global_hash)
    print("")
    veetee(global_hash, hash_flag=True)
if global_url != 'skip':
    print("Report for: " + global_url)
    print("")
    veetee(global_url,url_flag=True)
    ipqs_url(global_url)
if global_email != 'skip':
    print("Report for: " + global_email)
    print("")
    ipqs_email(global_email)

    
