#!/bin/bash



## VARIABLES
ToolsDIR="/bounty/tools"
ResultsPath="/bounty/output/domain/"
mkdir -p $ResultsPath
TransferSH="https://transfer.sh"
subjackDebug="/bounty/tools/subjack/fingerprints.json"

## FUNCTION
die() {
    printf '%s\n' "$1" >&2
    exit 1 
}

help() {
  banner
  echo -e "Usage : ./recon.sh -d domain -m -s -u
      -d | --domain  (required) : Launch passive scan (Passive Amass, Aquatone, Subjack, TkoSubs, CORStest)
      -m | --masscan (optional) : Launch masscan (Can be very long & very aggressive ...)
      -s | --dirsearch (optional) : Launch dirsearch (with threads 100)
      -u | --upload  (optional) : Upload archive on Transfer.sh
  "
}

banner() {
  echo -e "
                _        _____                      
     /\        | |      |  __ \                     
    /  \  _   _| |_ ___ | |__) |___  ___ ___  _ __  
   / /\ \| | | | __/ _ \|  _  // _ \/ __/ _ \| '_ \ 
  / ____ \ |_| | || (_) | | \ \  __/ (_| (_) | | | |
 /_/    \_\__,_|\__\___/|_|  \_\___|\___\___/|_| |_|
 "
}

scan() {
  banner
  echo -e "Scan is in \e[31mprogress\e[0m, take a coffee"

  ## ENUM SUB-DOMAINS
  slack chat send $(TZ=IST-5:30 date) '#bounty'
  echo -e ">> Passive subdomains enumeration with \e[36mAmass\e[0m, \e[36mCertspotter\e[0m & \e[36mCrt.sh\e[0m"
  $ToolsDIR/amass/amass enum -d $domain -passive -max-dns-queries 200 -r 1.1.1.1,8.8.8.8 -o $ResultsPath/$domain/passive.txt > /dev/null 2>&1
  $ToolsDIR/amass/amass enum -d $domain -brute -max-dns-queries 200 -r 1.1.1.1,8.8.8.8 -o $ResultsPath/$domain/brute.txt > /dev/null 2>&1
  $ToolsDIR/amass/amass enum -d $domain -active -max-dns-queries 200 -r 1.1.1.1,8.8.8.8 -o $ResultsPath/$domain/active.txt > /dev/null 2>&1
  curl -s https://certspotter.com/api/v0/certs\?domain\=$domain | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u  >> $ResultsPath/$domain/certspotter.txt > /dev/null 2>&1
  curl -s "https://crt.sh/?q=%.$domain&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort | uniq >> $ResultsPath/$domain/crtsh.txt > /dev/null 2>&1
  curl -s "https://crt.sh/?q=%.%.%.%.$domain&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort | uniq >> $ResultsPath/$domain/crtsh.txt > /dev/null 2>&1
  waybackurls $domain | awk -F[/:] '{print $4}' | sort -u >> $ResultsPath/$domain/waybackurls.txt > /dev/null 2>&1
  cd /bounty/tools/punter/ ; python main.py -t $domain > /dev/null 2>&1


  cat $ResultsPath/$domain/passive.txt $ResultsPath/$domain/active.txt $ResultsPath/$domain/brute.txt $ResultsPath/$domain/certspotter.txt $ResultsPath/$domain/crtsh.txt $ResultsPath/$domain/waybackurls.txt >> $ResultsPath/$domain/$domain_tmp1.txt
  #rm $ResultsPath/$domain/passive.txt $ResultsPath/$domain/active.txt $ResultsPath/$domain/brute.txt $ResultsPath/$domain/certspotter.txt $ResultsPath/$domain/crtsh.txt $ResultsPath/$domain/waybackurls.txt
  sort $ResultsPath/$domain/$domain_tmp1.txt | uniq > $ResultsPath/$domain/domains_tmp2.txt
  #rm $ResultsPath/$domain/$domain_tmp1.txt

    ## CHECK RESULTS WITH MASSDNS
  echo -e ">> Check results with \e[36mMassDNS\e[0m"
  printf "8.8.8.8\n1.1.1.1" > $ToolsDIR/MassDNS/resolvers.txt
  $ToolsDIR/MassDNS/bin/massdns -r $ToolsDIR/MassDNS/resolvers.txt -t A -o S -w $ResultsPath/$domain/massdns.txt $ResultsPath/$domain/domains_tmp2.txt > /dev/null 2>&1
  #rm $ResultsPath/$domain/domains_tmp2.txt

  ## CLEAN MASSDNS RESULTS
  grep -Po "([A-Za-z0-9]).*$domain" $ResultsPath/$domain/massdns.txt > $ResultsPath/$domain/tmp_domains.txt
  sed 's/\..CNAME.*/ /g' $ResultsPath/$domain/tmp_domains.txt > $ResultsPath/$domain/tmp2_domains.txt
  sed 's/CNAME.*/ /g' $ResultsPath/$domain/tmp2_domains.txt ; sort -u > $ResultsPath/$domain/domains.txt
  rm $ResultsPath/$domain/tmp_domains.txt $ResultsPath/$domain/tmp2_domains.txt
  slack file upload $ResultsPath/$domain/domains.txt '#bounty'


  ## CHECK TAKEOVER WITH SUBJACK AND TKOSUBS
  echo -e ">> Checking takeover with \e[36mSubjack\e[0m & \e[36mTkoSubs\e[0m"
  subjack -w $ResultsPath/$domain/domains.txt -t 100 -o $ResultsPath/$domain/Subjack.txt -c $subjackDebug -v -ssl > /dev/null 2>&1
  tko-subs -domains=$ResultsPath/$domain/domains.txt -data=$ToolsDIR/TkoSubs/providers-data.csv -output=$ResultsPath/$domain/TkoSubs.csv > /dev/null 2>&1


  ## GET IP OF EACH DOMAINS
  for ip in $(cat $ResultsPath/$domain/domains.txt) ; do dig +short $rline ;  grep '^[.0-9]*$' >> $ResultsPath/$domain/IP.txt
  done
   #grep '^[.0-9]*$'
  cat $ResultsPath/$domain/IP.txt | sort -u > $ResultsPath/$domain/IPs.txt
  rm $ResultsPath/$domain/IP.txt

  if [ -v masscan ]
    then
      echo -e ">> Checking open ports with \e[36mMasscan\e[0m"
      ## LAUNCH MASSCAN
      masscan -p1-65535,U:1-65535 -iL $ResultsPath/$domain/IPs.txt --rate=100000 -oJ $ResultsPath/$domain/masscan.json
      slack file upload $ResultsPath/$domain/masscan.json '#bounty'
    
  fi

  for ip in $(cat $ResultsPath/$domain/IPs.txt) ; do shodan host $ip ; sleep 1 ; done >>$ResultsPath/$domain/shodan.txt 
  	  slack file upload $ResultsPath/$domain/shodan.txt '#bounty'

    ## LAUNCH AQUATONE
  echo -e ">> Launch \e[36mAquatone\e[0m scan"
  cat $ResultsPath/$domain/domains.txt | $ToolsDIR/aquatone -out $ResultsPath/$domain/aquatone/ -ports xlarge -save-body false > /dev/null 2>&1
  slack file upload $ResultsPath/$domain/aquatone/aquatone_urls.txt '#bounty'


  if [ -v dirsearch ]
  then
  	mkdir -p $ResultsPath/$domain/dirsearch
    echo -e ">> Checking open ports with \e[36mMasscan\e[0m"
     cat $ResultsPath/$domain/domains.txt | while read line ;
    do
      python3 $ToolsDIR/DirSearch/dirsearch.py -e . -t 200 -u https://$line -rf -x 400,403,404,500,503,304 --simple-report=$ResultsPath/$domain/dirsearch/$line.txt
    done

   fi 


  ## CREATE AN ARCHIVE
  tar czvf $ResultsPath/$domain/$domain.tar.gz $ResultsPath/$domain/* > /dev/null 2>&1

  echo -e "\n=========== Scan is \e[32mfinish\e[0m ==========="
  echo -e "Archive of scan was create, path : \e[36m$ResultsPath/$domain/$domain.tar.gz\e[0m"

  if [ -v upload ] ## IF UPLOAD OPTION WAS PROVIDE
  then
    slack chat send $(curl -H "Max-Downloads: 1" -H "Max-Days: 15" --upload-file $ResultsPath/$domain/$domain.tar.gz $TransferSH/$domain.tar.gz) '#bounty'
    
  fi
  	slack chat send $(TZ=IST-5:30 date) '#bounty'
}

while :; do
    case $1 in
        -h|-\?|--help)
            help
            exit
            ;;
        -d|--domain)
            if [ "$2" ]; then
                domain=$2
                shift
            else
                die 'ERROR: "--domain" requires a non-empty option argument.'
            fi
            ;;
        --domain=)
            die 'ERROR: "--domain" requires a non-empty option argument.'
            ;;
        -m|--masscan)
            masscan=true
            ;;
        -s|--dirsearch)
            dirsearch=true
            ;;
        -u|--upload)
            upload=true
            ;;
        --)
            shift
            break
            ;;
        -?*)
            printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
            ;;
        *)
            break
    esac

    shift
done

if [ -z "$domain" ]
then
  help
  die 'ERROR: "--domain" requires a non-empty option argument.'
else
  if [ ! -d "$ResultsPath/$domain" ];then
    mkdir $ResultsPath/$domain
  else
    while true; do
        echo -e "The dir \e[36m$ResultsPath/$domain\e[0m already exists, delete ? [y/n]"
        read -p ">> " yn
        case $yn in
            [Yy]* ) sudo rm -r $ResultsPath/$domain; mkdir $ResultsPath/$domain;  break;;
            [Nn]* ) break;;
            * ) echo "Please answer y or n.";;
        esac
    done
  fi
  scan
fi
