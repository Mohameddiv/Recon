echo "###################################################"
echo "#    __  ____   __  ____  _____ ____ ___  _   _   #"
echo "#   |  \/  \ \ / / |  _ \| ____/ ___/ _ \| \ | |  #"
echo "#   | |\/| |\ V /  | |_) |  _|| |  | | | |  \| |  #"
echo "#   | |  | | | |   |  _ <| |__| |__| |_| | |\  |  #"
echo "#   |_|  |_| |_|   |_| \_\_____\____\___/|_| \_|  #"
echo "#                                                 #" 
echo "###################################################"
                                    
                           
                    

echo "                                                 "
echo "Enter your domain:"
read domain
cd domain
mkdir $domain
cd $domain
mkdir subs 
mkdir vul 
mkdir vul/payload
mkdir vul/nuclei
mkdir vul/payload/lfi
mkdir js 
mkdir crawl 
mkdir network
mkdir Fuzzing
echo "#################################################"
echo "Starting Subdomain Enumeation.." 
subfinder -d $domain -silent -o /home/mohamed/Recon/domain/$domain/subs/subfinder.txt
cd /home/mohamed/Recon/domain/$domain/subs/
findomain -t $domain -o 
cd ..
amass enum -passive -norecursive -noalts -d $domain  -o /home/mohamed/Recon/domain/$domain/subs/amass.txt
assetfinder -subs-only $domain >> /home/mohamed/Recon/domain/$domain/subs/assetfinder.txt
python3 /home/mohamed/tools/Sublist3r/sublist3r.py -d $domain -o /home/mohamed/Recon/domain/$domain/subs/sublist3r.txt
gobuster dns -d $domain -o /home/mohamed/Recon/domain/$domain/subs/brute.txt -w /usr/share/wordlist/dirbuster/directories.jbrofuzz
crt.sh $domain /home/mohamed/Recon/domain/$domain/subs/crt.txt
cat subs/*.txt| sort -u >> /home/mohamed/Recon/domain/$domain/subs/all-subs.txt
echo "#################################################"
echo "Starting HTTPX.."
cat subs/all-subs.txt | httpx -ports 80,443,8080,8000,8081,8008,8888,8443,9000,9001,9090 -silent |sort -u >> /home/mohamed/Recon/domain/$domain/subs/live-subs.txt
cat subs/all-subs.txt | httpx -mc 404 -silent |sort -u >> /home/mohamed/Recon/domain/$domain/subs/404-subs.txt
cat subs/live-subs.txt | httpx -mc 200 -silent |sort -u >> /home/mohamed/Recon/domain/$domain/subs/200-subs.txt

httpx -l /home/mohamed/Recon/domain/$domain/subs/live-subs.txt -pa -silent -o /home/mohamed/Recon/domain/$domain/network/url-ip.txt
cat /home/mohamed/Recon/domain/$domain/network/url-ip.txt| grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'| sort -u >>/home/mohamed/Recon/domain/$domain/network/ip.txt
echo "#################################################"
echo "Starting network .."
nmap -sV -T3 -Pn -top-port 200 -iL /home/mohamed/Recon/domain/$domain/network/ip.txt > /home/mohamed/Recon/domain/$domain/network/nmap.txt
#nmap --script "http-*" -p 443 -iL /home/mohamed/Recon/domain/$domain/network/ip.txt >>/home/mohamed/Recon/domain/$domain/network/nmap2.txt
echo "#################################################"
echo "Starting Gowitness .."
gowitness file -f /home/mohamed/Recon/domain/$domain/subs/live-subs.txt
echo "#################################################"
echo "Starting Crawling Paramters.."
#gospider -S /home/mohamed/Recon/domain/$domain/subs/live-subs.txt -d 10 -c 20 -t 50 -K 3 --no-redirect --js -a -w --blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" --include-subs -q -o /home/mohamed/Recon/domain/$domain/crawl/gospider
#xargs -a /home/mohamed/Recon/domain/$domain/subs/live-subs.txt -P 50 -I % bash -c "echo % | waybackurls" >> /home/mohamed/Recon/domain/$domain/crawl/waybackurls.txt
python3 /mnt/sda2/Tools/ParamSpider/paramspider.py --domain $domain --level high -s True -e eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,svg,txt -o /home/mohamed/Recon/domain/$domain/crawl/paramspider.txt
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |waybackurls >> /home/mohamed/Recon/domain/$domain/crawl/wayback.txt 
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |hakrawler >> /home/mohamed/Recon/domain/$domain/crawl/hakrawler.txt 
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |gau >> /home/mohamed/Recon/domain/$domain/crawl/gau.txt 
#cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars";done | grep "xss">> /home/mohamed/Recon/domain/$domain/crawl/js-param.txt

cat /home/mohamed/Recon/domain/$domain/crawl/*.txt| grep $domain |grep -v "js\|css\|eot\|jpg\|jpeg\|gif\|css\|tif\|tiff\|png\|ttf\|otf\|woff\|woff2\|ico\|svg\|txt" | grep "=" | sort -u | anew -q /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt

echo "#################################################"
echo "Starting GF.."
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf xss | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/xss.txt
##cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf sqli | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/sql.txt
##cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf redirect | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/redirect.txt
##cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf lfi| qsreplace >> /home/mohamed/Recon/domain/$domain/vul/lfi.txt
##cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf ssrf | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/ssrf.txt
##cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf ssti | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/ssti.txt
##cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf rce | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/rce.txt
cat /home/mohamed/Recon/domain/$domain/vul/*.txt | sort -u >>/home/mohamed/Recon/domain/$domain/vul/vul-urls.txt

#cat /mnt/sda2/PayloadsAllTheThings-master/ssti/Intruder/ssti.fuzz | while read -r line; do
#cat /home/mohamed/Recon/domain/$domain/vul/ssti.txt | qsreplace "$line"| anew -q /home/mohamed/Recon/domain/$domain/vul/payload/ssti.txt
#done
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt | while read -r line; do
curl $line | grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" | sort -u |grep -v "eot\|jpg\|jpeg\|gif\|css\|tif\|tiff\|png\|ttf\|otf\|woff\|woff2\|ico\|svg\|txt" | burl >>/home/mohamed/Recon/domain/$domain/vul/broken-links.txt
done 


#cat /home/mohamed/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt | while read -r line; do
#cat /home/mohamed/Recon/domain/$domain/vul/lfi.txt | qsreplace "$line" | anew -q /home/mohamed/Recon/domain/$domain/vul/payload/lfi.txt
#done
#cd /home/mohamed/Recon/domain/$domain/vul/payload/lfi/
#cat /home/mohamed/Recon/domain/$domain/vul/payload/lfi.txt | while read -r line; do
#wget -t 1 -T 5 $line 
#done
#cd /home/mohamed/Recon/domain/$domain/
cat /home/mohamed/Recon/domain/$domain/vul/xss.txt  | kxss | grep "<\|>" | anew -q /home/mohamed/Recon/domain/$domain/vul/payload/xss.txt
cat /home/mohamed/Recon/domain/$domain/vul/xss.txt | qsreplace '"><script>alert(123)</script>' | freq | grep -v "Not">> /home/mohamed/Recon/domain/$domain/vul/payload/xss2.txt
#cat /home/mohamed/Recon/domain/$domain/vul/redirect.txt | qsreplace "http://www.evil.com/" | anew -q /home/mohamed/Recon/domain/$domain/vul/payload/redirect.txt
echo "#################################################"
echo "Starting JS Scanning.."
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt  |JSFScan.sh -all -r -o /home/mohamed/Recon/domain/$domain/js/JSFScan
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt | getJS --complete | sort -u|tee /home/mohamed/Recon/domain/$domain/js/js1.txt
python /mnt/sda2/Tools/secretfinder/SecretFinder.py -i /home/mohamed/Recon/domain/$domain/js/js1.txt -o /home/mohamed/Recon/domain/$domain/js/secrets1.html
cat /home/mohamed/Recon/domain/$domain/js/js-url.txt | nuclei -t /home/mohamed/nuclei-templates/exposures/ -o /home/mohamed/Recon/domain/$domain/js/secrets2.txt
echo "#################################################"
echo "Starting Takeover.."
cd /mnt/sda2/Tools/SubOver/
./SubOver -l /home/mohamed/Recon/domain/$domain/subs/404-subs.txt -o /home/mohamed/Recon/domain/$domain/vul/takeover1.txt
cd /home/mohamed/Recon/domain/$domain/
#echo "#################################################"
#echo "Start SSLscanning.."
#nmap --script ssl-enum-ciphers -p 443 -iL /home/mohamed/Recon/domain/$domain/network/ip.txt
#sslscan --targets /home/mohamed/Recon/domain/$domain/subs/all-subs.txt | grep heartbleed #there is error here...
echo "#################################################"
echo "Starting DIR_FUZZING.."
cat /home/mohamed/Recon/domain/$domain/subs/200-subs.txt|while read -r line;do
ffuf -u $line/FUZZ -w /home/mohamed/fuzz.txt -mc 200 -o /home/mohamed/Recon/domain/$domain/fuzzing/$line.txt
done
echo "#################################################"
echo "Starting Nuclei.."
echo "info"
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |nuclei -t /home/mohamed/nuclei-templates/ -nc -severity info -c 50 -silent | anew -q /home/mohamed/Recon/domain/$domain/vul/nuclei/info.txt
echo "low"
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |nuclei -t /home/mohamed/nuclei-templates/ -nc -severity low -c 50 -silent | anew -q /home/mohamed/Recon/domain/$domain/vul/nuclei/low.txt
echo "medium"
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |nuclei -t /home/mohamed/nuclei-templates/ -nc -severity medium -c 50 -silent | anew -q /home/mohamed/Recon/domain/$domain/vul/nuclei/medium.txt
echo "high"
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |nuclei -t /home/mohamed/nuclei-templates/ -nc -severity high -c 50 -silent | anew -q /home/mohamed/Recon/domain/$domain/vul/nuclei/high.txt
echo "critical"
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt |nuclei -t /home/mohamed/nuclei-templates/ -nc -severity critical -c 50 -silent | anew -q /home/mohamed/Recon/domain/$domain/vul/nuclei/critical.txt


