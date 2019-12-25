#!/bin/bash
export DEBIAN_FRONTEND=noninteractive;
echo "[*] Starting Install... [*]"
echo "[*] Upgrade installed packages to latest [*]"
echo -e "\nRunning a package upgrade...\n"
sudo apt-get -qq update && apt-get -qq dist-upgrade -y
sudo apt full-upgrade -y
sudo apt-get autoclean


mkdir -p /bounty/tools/
mkdir -p /bounty/wordlist/

echo "[*] Install stuff I use all the time [*]"
echo -e "\nInstalling default packages...\n"
sudo add-apt-repository ppa:duh/golang
sudo apt-get -y install build-essential checkinstall fail2ban gcc firefox git sqlite3 ruby ruby-dev git-core python-dev python-pip unzip jruby libbz2-dev libc6-dev libgdbm-dev libncursesw5-dev libreadline-gplv2-dev libsqlite3-dev libssl-dev nmap nodejs python-dev python-numpy python-scipy python-setuptools tk-dev unattended-upgrades wget curl
sudo apt-get install -y xvfb x11-xkb-utils xfonts-100dpi xfonts-75dpi xfonts-scalable xfonts-cyrillic x11-apps clang libdbus-1-dev libgtk2.0-dev libnotify-dev libgnome-keyring-dev libgconf2-dev libasound2-dev libcap-dev libcups2-dev libxtst-dev libxss1 libnss3-dev gcc-multilib g++-multilib libldns-dev
sudo apt-get install -y dnsutils python3-pip  libavahi-compat-libdnssd1 git-core libldns-dev python-software-properties golang gobuster masscan stem  tor netcat privoxy python-pip python3-uritools python3-paramiko nfs-common eyewitness nodejs wafw00f xdg-utils metagoofil clusterd ruby-full rubygems python dos2unix sslyze arachni aha libxml2-utils rpcbind cutycapt host whois dnsrecon  php php-curl hydra wpscan sqlmap nbtscan enum4linux cisco-torch metasploit-framework theharvester dnsenum nikto smtp-user-enum whatweb sslscan jq golang adb xsltproc
sudo pip install dnspython colorama tldextract urllib3 ipaddress requests html eventlet termcolor
sudo pip3 install jsbeautifier eventlet termcolor numpy fuzzywuzzy python-Levenshtein shodan wafw00f
gem install aquatone

echo "[*] bash changes [*]"
bind "set completion-ignore-case on"
bind "set show-all-if-ambiguous on"



echo "[*] Install go[*]"
cd /usr/share/go
wget https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
sudo tar -xvf go1.12.6.linux-amd64.tar.gz
export GOROOT=/usr/share/go >> ~/.profile
export GOPATH=$root/go >> ~/.profile
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin >> ~/.profile
source ~/.profile


echo "[*] Install go tools[*]"
go get github.com/OJ/gobuster
go get github.com/tomnomnom/hacks/filter-resolved
go get -u github.com/tomnomnom/httprobe

cd /bounty/tools/
echo "[*] Install amass[*]"
wget https://github.com/OWASP/Amass/releases/download/v3.0.23/amass_v3.0.23_linux_amd64.zip
unzip amass_v3.0.23_linux_amd64.zip -d $tools/
rm amass_v3.0.23_linux_amd64.zip
mv $tools/amass_v3.0.23_linux_amd64 $tools/amass

echo "[*] Install Chrome.[*]"
wget -N https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -P ~/
dpkg -i --force-depends ~/google-chrome-stable_current_amd64.deb
apt-get -f install -y
dpkg -i --force-depends ~/google-chrome-stable_current_amd64.deb

echo "[*] Install Ruby[*]"
apt-get -qq install gnupg2 -y
curl -sSL https://rvm.io/mpapis.asc | gpg --import -
curl -L https://get.rvm.io | bash -s stable --ruby
echo "source /usr/local/rvm/scripts/rvm" >> ~/.bashrc

echo "[*] Install nodejs [*]"
curl -sL https://deb.nodesource.com/setup_8.x | bash -
apt-get install -y nodejs

echo "[*] Install PhantomJs[*]"
curl -L https://gist.githubusercontent.com/ManuelTS/935155f423374e950566d05d1448038d/raw/906887cbfa384d450276b87087d28e6a51245811/install_phantomJs.sh | sh

echo "[*] Install Casperjs[*]"
git clone git://github.com/n1k0/casperjs.git
cd casperjs
ln -sf `pwd`/bin/casperjs /usr/local/bin/casperjs


cd /bounty/tools/
echo "[*] install Sublist3r[*]"
git clone https://github.com/Plazmaz/Sublist3r.git
sudo pip install -r Sublist3r/requirements.txt

cd /bounty/tools/
echo "[*] Install dirsearch[*]"
git clone https://github.com/maurosoria/dirsearch 
#ln -sf dirsearch.py /bin/dirsearch /usr/local/bin/dirsearch

echo "[*] Install lazys3[*]"
git clone https://github.com/nahamsec/lazys3 
cd lazys3 
#ln -sf `pwd` /bin/lazys3 /usr/local/bin/lazys3

cd /bounty/tools/
echo "[*] Install LinkFinder[*]"
git clone https://github.com/GerbenJavado/LinkFinder.git 
cd LinkFinder 
sudo python setup.py install 
#ln -sf `pwd` /bin/linkfinder /usr/local/bin/linkfinder

cd /bounty/tools/
echo "[*] Install Common crowl[*]"
git clone https://github.com/si9int/cc.py.git 
#ln -sf `pwd` /bin/cc /usr/local/bin/cc


cd /bounty/wordlist
echo "[*] Install Wordlists[*]"
git clone https://gist.github.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7
git clone https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10
mv 96fb9e934fc16415fbda2f83f08b28e7/* ./1.txt
mv b80ea67d85c13206125806f0828f4d10/* ./2.txt
sudo rm -rf 96fb9e934fc16415fbda2f83f08b28e7 b80ea67d85c13206125806f0828f4d10

cd /bounty/tools/
echo "[*] Install fuxploider[*]"
git clone https://github.com/almandin/fuxploider.git
sudo pip3 install -r fuxploider/requirements.txt
sudo pip install -r fuxploider/requirements.txt
#ln -sf `pwd` /bin/fuxploider /usr/local/bin/fuxploider

cd /bounty/tools/
echo "[*] Install parameth[*]"
git clone https://github.com/mak-/parameth
cd parameth
virtualenv venv
. ./venv/bin/activate
sudo pip install -r requirements.txt
sudo pip3 install -r requirements.txt
#ln -sf `pwd`/bin/parameth /usr/local/bin/parameth

cd /bounty/tools/
echo "[*] Install CMSeeK[*]"
git clone https://github.com/Tuhinshubhra/CMSeeK
sudo pip install -r CMSeeK/requirements.txt
#ln -sf `pwd` /bin/cmseek /usr/local/bin/cmseek

cd /bounty/tools/
echo "[*] Install GitTools[*]"
git clone https://github.com/internetwache/GitTools
sudo pip3 install -r GitTools/Finder/requirements.txt
#ln -sf `pwd` /bin/gitfinder /usr/local/bin/gitfinder

#https://github.com/wireghoul/dotdotpwn

#cd /bounty/tools/
#echo "[*] Install wig [*]"
#git clone https://github.com/jekyc/wig
#cd wig
#sudo python3 setup.py install
#ln -sf `pwd` /bin/wig /usr/local/bin/wig

cd /bounty/tools/
echo "[*] Install vulscan [*]"
git clone https://github.com/scipag/vulscan
sudo ln -sf `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan
mkdir tmp && cd tmp
wget https://www.computec.ch/projekte/vulscan/download/cve.csv
wget https://www.computec.ch/projekte/vulscan/download/exploitdb.csv
wget https://www.computec.ch/projekte/vulscan/download/openvas.csv
wget https://www.computec.ch/projekte/vulscan/download/osvdb.csv
wget https://www.computec.ch/projekte/vulscan/download/scipvuldb.csv
wget https://www.computec.ch/projekte/vulscan/download/securityfocus.csv
wget https://www.computec.ch/projekte/vulscan/download/securitytracker.csv
wget https://www.computec.ch/projekte/vulscan/download/xforce.csv
mv * /usr/share/nmap/scripts/vulscan
echo "files moved"
cd .. && rm -rf tmp

cd /bounty/tools/
echo "[*] Install konan [*]"
git clone https://github.com/m4ll0k/Konan.git konan
sudo pip install -r konan/requirements.txt
#ln -sf `pwd` /bin/konan /usr/local/bin/konan

cd /bounty/tools/
echo "[*] Install CRLF-Injection-Scanner [*]"
#git clone https://github.com/MichaelStott/CRLF-Injection-Scanner
cd CRLF-Injection-Scanner
#echo "updated payloads"
#echo "ESCAPE_LIST = ['%%0a0a', '%0a', '%0d%0a', '%0d', '%23%0a', '%23%0d%0a', '%23%0d', '%25%30%61', '%25%30a', '%250a', '%25250a', '%2e%2e%2f%0d%0a', '%2f%2e%2e%0d%0a', '%2F..%0d%0a', '%3f%0d%0a', '%3f%0d', '%u000a']" > crlf.txt
#cho "same code and payloads updated"
wget https://pastebin.com/raw/cCWx6b2s -O crlf.py


cd /bounty/tools/
echo "[*] Install droopescan [*]"
git clone https://github.com/droope/droopescan
cd droopescan
python setup.py install
sudo pip install -r requirements_test.txt
sudo pip install -r requirements.txt

cd /bounty/tools/
echo "[*] Install joomscan [*]"
git clone https://github.com/rezasp/joomscan.git

cd /bounty/tools/
echo "[*] Install subbrute [*]"
git clone https://github.com/TheRook/subbrute

cd /bounty/tools/
echo "[*] Install domained [*]"
git clone https://github.com/TypeError/domained
cd domained
sudo python3 domained.py --install
sudo pip3 install -r ./ext/requirements.txt

cd /bounty/tools/
echo "[*] Install MassDNS [*]"
git clone https://github.com/blechschmidt/massdns.git /bounty/tools/MassDNS
mkdir -p /bounty/tools/MassDNS/bin
cc  -O3 -std=c11 -DHAVE_EPOLL -DHAVE_SYSINFO -Wall -fstack-protector-strong /bounty/tools/MassDNS/main.c -o /bounty/tools/MassDNS/bin/massdns

cd /bounty/tools/
echo "[*] Install MassDNS [*]"
git clone https://github.com/guelfoweb/knock.git
cd knock
sudo python setup.py install

echo "[*] Install api keys [*]"
aquatone-discover --set-key shodan <key>

cd /bounty/tools/
echo "[*] Install waybackurls [*]"
wget https://github.com/tomnomnom/waybackurls/releases/download/v0.0.2/waybackurls-linux-amd64-0.0.2.tgz
tar -xvf waybackurls-linux-amd64-0.0.2.tgz
