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
mkdir wayback
mkdir vul 
mkdir vul/payload
mkdir vul/nuclei
mkdir fuzzing 
mkdir crawl 
mkdir network
mkdir ports
echo "#################################################"
echo "Starting Subdomain Enumeation.."
subfinder -d $domain -silent -o /home/mohamed/Recon/domain/$domain/subs/subfinder.txt
cd /home/mohamed/Recon/domain/$domain/subs/
findomain -t $domain -o 
cd ..
assetfinder -subs-only $domain >> /home/mohamed/Recon/domain/$domain/subs/assetfinder.txt
python3 /home/mohamed/tools/Sublist3r/sublist3r.py -d $domain -o /home/mohamed/Recon/domain/$domain/subs/sublist3r.txt
cat subs/*.txt| sort -u >> /home/mohamed/Recon/domain/$domain/subs/all-subs.txt
echo "#################################################"
echo "Starting HTTPX.."
cat subs/all-subs.txt | httpx -silent >> /home/mohamed/Recon/domain/$domain/subs/live-subs.txt
httpx -l /home/mohamed/Recon/domain/$domain/subs/live-subs.txt -pa -silent -o /home/mohamed/Recon/domain/$domain/network/url-ip.txt
cat /home/mohamed/Recon/domain/$domain/network/url-ip.txt| grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'| sort -u >>/home/mohamed/Recon/domain/$domain/network/ip.txt
echo "#################################################"
echo "Starting network .."
nmap -sV -T3 -Pn -top-port 200 -iL /home/mohamed/Recon/domain/$domain/network/ip.txt |  grep -E 'open|filtered|closed' > /home/mohamed/Recon/domain/$domain/network/nmap.txt
nmap --script "http-*" -p 443 -iL /home/mohamed/Recon/domain/$domain/network/ip.txt >>/home/mohamed/Recon/domain/$domain/network/nmap2.txt
echo "#################################################"
echo "Starting Crawling Paramters.."
#gospider -S /home/mohamed/Recon/domain/$domain/subs/live-subs.txt -d 10 -c 20 -t 50 -K 3 --no-redirect --js -a -w --blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" --include-subs -q -o /home/mohamed/Recon/domain/$domain/crawl/gospider
#xargs -a /home/mohamed/Recon/domain/$domain/subs/live-subs.txt -P 50 -I % bash -c "echo % | waybackurls" >> /home/mohamed/Recon/domain/$domain/crawl/waybackurls.txt
python3 /mnt/sda2/Tools/ParamSpider/paramspider.py --domain $domain -e eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,svg,txt -o /home/mohamed/Recon/domain/$domain/crawl/paramspider.txt
waybackurls $domain |grep -v "eot\|jpg\|jpeg\|gif\|css\|tif\|tiff\|png\|ttf\|otf\|woff\|woff2\|ico\|svg\|txt" | grep "=" >> /home/mohamed/Recon/domain/$domain/crawl/wayback-param.txt 
cat /home/mohamed/Recon/domain/$domain/subs/live-subs.txt | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars";done | grep "xss" | sort -u >> /home/mohamed/Recon/domain/$domain/crawl/js-param.txt
cat /home/mohamed/Recon/domain/$domain/crawl/*.txt| grep $domain | sort -u | anew -q /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt
echo "#################################################"
echo "Starting GF.."
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf xss | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/xss.txt
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf sqli | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/sql.txt
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf redirect | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/redirect.txt
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf lfi| qsreplace >> /home/mohamed/Recon/domain/$domain/vul/lfi.txt
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf ssrf | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/ssrf.txt
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf ssti | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/ssti.txt
cat /home/mohamed/Recon/domain/$domain/crawl/all-paramters.txt| gf rce | qsreplace>> /home/mohamed/Recon/domain/$domain/vul/rce.txt

cat /mnt/sda2/PayloadsAllTheThings-master/ssti/Intruder/ssti.fuzz | while read -r line; do
cat /home/mohamed/Recon/domain/$domain/vul/ssti.txt | qsreplace "$line"| anew -q /home/mohamed/Recon/domain/$domain/vul/payload/ssti.txt
done

cat /home/mohamed/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt | while read -r line; do
cat /home/mohamed/Recon/domain/$domain/vul/lfi.txt | qsreplace "$line" | anew -q /home/mohamed/Recon/domain/$domain/vul/payload/lfi.txt
done
cat /home/mohamed/Recon/domain/$domain/vul/xss.txt  | kxss | grep "<\|>" | anew -q /home/mohamed/Recon/domain/$domain/vul/payload/xss.txt
cat /home/mohamed/Recon/domain/$domain/vul/redirect.txt | qsreplace "http://www.evil.com/" | anew -q /home/mohamed/Recon/domain/$domain/vul/payload/redirect.txt
echo "#################################################"
echo "Starting Takeover.."
#SubOver -l subs/all-subs.txt -o vul/takeover1.txt
echo "#################################################"

echo "Start SSLscanning.."
#nmap --script ssl-enum-ciphers -p 443 -iL /home/mohamed/Recon/domain/$domain/network/ip.txt
sslscan --targets /home/mohamed/Recon/domain/$domain/subs/all-subs.txt | grep heartbleed #there is error here...
echo "#################################################"
echo "Starting Dirsearch.."
dirsearch -l /home/mohamed/Recon/domain/$domain/subs/live-subs.txt -o /home/mohamed/Recon/domain/$domain/fuzzing/
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


