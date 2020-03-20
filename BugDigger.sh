##!/bin/bash

banner = '
__________            ________  .__                            
\______   \__ __  ____\______ \ |__| ____   ____   ___________ 
 |    |  _/  |  \/ ___\|    |  \|  |/ ___\ / ___\_/ __ \_  __ \
 |    |   \  |  / /_/  >    `   \  / /_/  > /_/  >  ___/|  | \/
 |______  /____/\___  /_______  /__\___  /\___  / \___  >__|   
        \/     /_____/        \/  /_____//_____/      \/       
'

usage = '
Script which starts multiple OSINT, Pentest tools for a given domain.

Usage: ./BugDigger.sh <domain_to_scan>

domain: e.g. aware7.de

Build by Moritz Gruber <moritz.gruber@posteo.de>
'

# print Banner and Usage
echo $banner
if [ -z "$1" ]
then
  echo  $usage
  exit 1
fi

echo "\n\n[+] Creating Folder for Scans"
# Create a Folder for all Scan
mkdir $1
cd $1

echo "\n\n[+] Starting amass"
# starting amass
/home/moe/Tools/amass/amass enum --passive -d $1 -o domains_$1

echo "\n\n[+] Start assetfinder"
# starting assetfinder
assetfinder --subs-only $1 | tee -a domains_$1

echo "\n\n[+] Start massdns"
# starting massdns 
~/Tools/massdns/scripts/subbrute.py ~/Tools/SecLists/Discovery/DNS/jhaddix-dns.txt $1 | ~/Tools/massdns/bin/massdns -r ~/Tools/massdns/lists/resolvers.txt -t A -o S -w massDNS_$1.txt

echo "\n\n[+] Start Subfinder"
# startting Subfinder
subfinder -d $1 -o domains_subfinder_$1
cat domains_subfinder_$1 | tee -a domain_$1
rm domain_subfinder_$1

echo "\n\n[+] Format Output"
# Format massdns Output
cat massDNS_$1.txt | cut -d ' ' -f1 | tee -a domain_$1

# removing duplicate entries
sort -u domains_$1 -o domains_$1

# filtering the domains
cat domains_$1 | filter-resolved | tee -a domains_$1.txt
rm domains_$1

# Scanning Hosts
mkdir nmap
echo "\n\n[+] Start nmap Scan"
nmap -sS -sV -iL domains_$1.txt -v -oA nmap/nmap_sS_sV_iL_$1

# checking for alive domains
echo "\n\n[+] Checking for alive Web domains:\n"
cat domains_$1.txt | ~/go/bin/httprobe -p http:81 -p http:8080 -p https:8443 | tee -a alive_$1.txt

# Searching HTPPS-Domains
cat alive_$1.txt | grep "https" | cut -d '/' -f3 | tee https_alive_$1.txt

# Checking Certs
echo "\n\n[+] Checking SSL-Certificates:\n"
mkdir SSLScans
while read p;do
  sslscan -no-colour $p | tee SSLScans/$p.txt
done < https_alive_$1.txt

echo "\n\n [+] Generating URLS:\n"
cat alive_$1.txt | waybackurls | tee -a wayback_$1.txt
cat alive_$1.txt | hakrawler -plain | tee -a hakrawler_$1.txt
cat wayback_$1.txt | tee -a urls_$1.txt
cat hakrawler_$1.txt | tee -a urls_$1.txt
sort -u urls_$1.txt -o urls_$1.txt

mkdir gobuster
while read p; do
  filename=$(echo $p | cut -d '/' -f3)
  gobuster dir -u "$p" -w ~/Tools/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt -f -e -r -k -o gobuster/gobuster_dir_$1_$filename.txt
  cat gobuster_dir_$1_$filename.txt | tee -a gobuster_$1.txt
done < alive_$1.txt

while read p; do
  filename=$(echo $p | cut -d '/' -f3)
  gobuster dir -u "$p" -w ~/Tools/SecLists/Discovery/Web-Content/raft-large-files-lowercase.txt -f -e -r -k -o gobuster/gobuster_files_$1_$filename.txt
  cat gobuster_files_$1_$filename.txt | tee -a gobuster_$1.txt
done < alive_$1.txt

cat gobuster_$1.txt | cut -d ' ' -f1 | tee -a urls_$1.txt

echo "\n\n[+] Checking for Vulns:\n"

cat urls_$1.txt | kxss | tee kxxs_$1.txt
cat urls_$1.txt | grep "url=" | tee ssrf_$1.txt
cat urls_$1.txt | grep "id=[\d]*" | tee idor_$1.txt

subjack -w alive_$1.txt -timeout 30 -o tmp_subdomain_takeover_$1.txt -ssl -v
cat subdomain_takeover_$1.txt | grep -v "\[Not Vulnerable\]" | tee subdomain_takeover_$1.txt
rm tmp_subdomain_takeover_$1.txt