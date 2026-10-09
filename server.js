// CyberShield AI Pro backend - Node 18+, PostgreSQL (pg) + Ollama (auto low-RAM fallback) + JWT
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),os=require('os');
/* ---------- .env loader (real env vars from the host always win; later duplicates in file win) ---------- */
const PRE={...process.env};
try{for(const l of fs.readFileSync(path.join(__dirname,'.env'),'utf8').split(/\r?\n/)){const m=l.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);if(m&&!l.trim().startsWith('#')&&!(m[1] in PRE))process.env[m[1]]=m[2].replace(/^(['"])(.*)\1$/,'$2')}}catch{}
const E=process.env,PROD=E.NODE_ENV==='production';
const PORT=+E.PORT||3100,HOST=E.HOST||'0.0.0.0',DATA=path.join(E.DATA_DIR||__dirname,'data');
fs.mkdirSync(DATA,{recursive:true});
let SECRET=E.JWT_SECRET;if(!SECRET){const f=path.join(DATA,'secret');try{SECRET=fs.readFileSync(f,'utf8')}catch{SECRET=crypto.randomBytes(32).toString('hex');fs.writeFileSync(f,SECRET,{mode:0o600})}}
/* ---------- JWT (HS256) ---------- */
const b64=o=>Buffer.from(typeof o==='string'?o:JSON.stringify(o)).toString('base64url'),sig=s=>crypto.createHmac('sha256',SECRET).update(s).digest('base64url');
const sign=e=>{const s=b64({alg:'HS256',typ:'JWT'})+'.'+b64({sub:e,exp:Math.floor(Date.now()/1e3)+30*86400});return s+'.'+sig(s)};
const verify=t=>{try{const[h,p,s]=String(t).split('.'),m=sig(h+'.'+p);if(!s||s.length!==m.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(m)))return null;const o=JSON.parse(Buffer.from(p,'base64url'));return o.exp*1e3>Date.now()?o.sub:null}catch{return null}};
const mac=s=>crypto.createHmac('sha256',SECRET).update('otp:'+s).digest('hex');
const hpw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
const pub=u=>({email:u.email,name:u.name,phone:u.phone?'******'+String(u.phone).slice(-4):'',joined:+u.joined,scans:u.scans,done:u.done||[]});
/* ---------- Storage: PostgreSQL, automatic JSON-file fallback ---------- */
let store;
async function initStore(){
 let pg;try{pg=require('pg')}catch{console.log('[db] "pg" package not installed (run npm install) -> JSON file storage')}
 if(pg&&(E.DATABASE_URL||E.DB_HOST)){try{
  const ssl=/^(1|true)$/i.test(E.DB_SSL||'')||/sslmode=require/.test(E.DATABASE_URL||'')?{rejectUnauthorized:false}:undefined;
  const pool=new pg.Pool(E.DATABASE_URL?{connectionString:E.DATABASE_URL,ssl,connectionTimeoutMillis:6000,query_timeout:8000}:{host:E.DB_HOST,port:+E.DB_PORT||5432,database:E.DB_NAME,user:E.DB_USER,password:E.DB_PASSWORD,ssl,connectionTimeoutMillis:6000,query_timeout:8000});pool.on('error',e=>console.log('[db] pool error:',e.message));
  await pool.query(`create table if not exists cs_users(email text primary key,name text not null,phone text,salt text not null,hash text not null,joined bigint not null,scans int not null default 0,done jsonb not null default '[]');create table if not exists cs_logs(id bigserial primary key,u text not null,type text,score int,at bigint);create index if not exists cs_logs_u on cs_logs(u,id)`);
  const U=r=>r&&{...r,joined:+r.joined};
  store={kind:'PostgreSQL',
   get:async e=>U((await pool.query('select * from cs_users where email=$1',[e])).rows[0]),
   byPhone:async p=>U((await pool.query('select * from cs_users where phone=$1',[p])).rows[0]),
   add:async u=>{await pool.query('insert into cs_users(email,name,phone,salt,hash,joined,scans,done) values($1,$2,$3,$4,$5,$6,0,$7)',[u.email,u.name,u.phone||null,u.salt,u.hash,u.joined,JSON.stringify(u.done)])},
   upd:async u=>{await pool.query('update cs_users set name=$2,scans=$3,done=$4 where email=$1',[u.email,u.name,u.scans,JSON.stringify(u.done)])},
   del:async e=>{await pool.query('delete from cs_logs where u=$1',[e]);await pool.query('delete from cs_users where email=$1',[e])},
   log:async(u,type,score)=>{await pool.query('insert into cs_logs(u,type,score,at) values($1,$2,$3,$4)',[u,type,score,Date.now()]);await pool.query('delete from cs_logs where u=$1 and id not in (select id from cs_logs where u=$1 order by id desc limit 200)',[u])},
   hist:async e=>(await pool.query('select type,score,at from cs_logs where u=$1 order by id desc limit 60',[e])).rows.map(r=>({...r,at:+r.at}))};
  console.log('[db] PostgreSQL connected');return}catch(e){console.log('[db] PostgreSQL FAILED:',e.message,'\n[db] -> using JSON file storage instead (data/db.json)'+(PROD?'\n[db] WARNING: on a cloud host this file is erased on redeploy. Set DATABASE_URL (Neon).':''))}}
 const F=path.join(DATA,'db.json');let db;try{db=JSON.parse(fs.readFileSync(F,'utf8'))}catch{db={users:[],logs:[]}}
 const save=()=>{fs.writeFileSync(F+'.tmp',JSON.stringify(db));fs.renameSync(F+'.tmp',F)};
 store={kind:'JSON file',get:async e=>db.users.find(u=>u.email===e),byPhone:async p=>db.users.find(u=>u.phone&&u.phone===p),add:async u=>{db.users.push(u);save()},upd:async()=>save(),
  del:async e=>{db.users=db.users.filter(u=>u.email!==e);db.logs=db.logs.filter(l=>l.u!==e);save()},
  log:async(u,type,score)=>{db.logs.push({u,type,score,at:Date.now()});const m=db.logs.filter(l=>l.u===u);if(m.length>200)db.logs.splice(db.logs.indexOf(m[0]),1);save()},
  hist:async e=>db.logs.filter(l=>l.u===e).slice(-60).reverse()}}
/* ---------- Ollama AI ---------- */
const KNOW=[
[/phish|fake (link|mail|email|site|website)|suspicious link|link click|smish/i,'PHISHING: Fake message/email/site that steals passwords, OTP or money. Signs: urgency, threats, spelling mistakes, look-alike domain (paypa1.com, sbi-kyc.xyz), shortened link, asks login/OTP. Do: do not click; open official app/site yourself; check domain carefully; report (Gmail: Report phishing; India: cybercrime.gov.in). If you already entered password: change it now, enable 2FA, log out other devices. If card/bank details entered: call bank at once.'],
[/otp|upi|gpay|phonepe|paytm|bank|card|cvv|atm|panam|paisa|money (gone|lost|deducted)/i,'BANK/UPI FRAUD: Never share OTP, PIN, CVV, card number, or UPI PIN. UPI PIN is ONLY for sending money; never needed to receive. "Collect request" from strangers = scam, decline. If money lost: (1) call 1930 immediately (golden hour: faster = better chance to freeze) (2) call bank, block card/UPI (3) file complaint at cybercrime.gov.in (4) keep screenshots, txn ID, phone number (5) visit bank/police with complaint copy.'],
[/digital arrest|cbi|police|customs|narcotics|parcel|fedex|court|video call.*(arrest|police)|arrest/i,'DIGITAL ARREST SCAM: Fraudsters pose as CBI/police/customs on video call saying your parcel has drugs or you are in a money-laundering case, demand money to "clear" it. There is NO such thing as digital arrest in Indian law; real agencies never take money or hold you on video call. Do: hang up, do not pay, do not share Aadhaar/bank details, tell family, call 1930, report on cybercrime.gov.in.'],
[/password|pass word|passphrase|2fa|two.?factor|authenticator|mfa|login secure/i,'PASSWORDS/2FA: Use 14+ characters or a 4-5 random-word passphrase, unique for every account. Use a password manager (Bitwarden, KeePass). Turn on 2FA everywhere, prefer authenticator app (Google/Microsoft Authenticator) or passkeys over SMS. Never reuse passwords; check leaks at haveibeenpwned.com. Do not share passwords, even with "support staff".'],
[/hack|hacked|account (takeover|stolen|compromis)|instagram|facebook|whatsapp|gmail|social media|unauthori[sz]ed login/i,'ACCOUNT HACKED: (1) Change password from a clean device (2) log out of all devices (3) enable 2FA (4) check recovery email/phone not changed (5) remove unknown apps/sessions (6) use official recovery: Instagram/Facebook "Hacked" help, Google account recovery, WhatsApp: register your number again and set two-step verification (7) warn contacts not to send money (8) report on cybercrime.gov.in if money or blackmail involved.'],
[/virus|malware|ransom|trojan|infected|spyware|keylogger|stalkerware|slow phone|pop.?up ads|adware/i,'MALWARE: Signs: slow device, pop-ups, unknown apps, battery drain, files locked. Do: disconnect from internet, boot safe mode, run full scan (Windows Defender / Malwarebytes), uninstall unknown apps and remove device-admin rights, change passwords from a clean device, restore from backup. Ransomware: do not pay, disconnect, keep the encrypted files, check nomoreransom.org. Worst case: factory reset. Prevention: avoid cracked software, update OS/apps, install only from official stores.'],
[/wi.?fi|wifi|vpn|public network|router|hotspot|free wifi/i,'WI-FI/VPN: Public Wi-Fi can be snooped; avoid banking there, use mobile data or a trusted VPN. Turn off auto-connect and file sharing. Home router: change default admin password, use WPA2/WPA3, update firmware, disable WPS, use a strong Wi-Fi password.'],
[/apk|fake app|loan app|instant loan|harass|morph|blackmail|sextortion|nude|video call.*(nude|record)|threat/i,'LOAN APP / SEXTORTION / BLACKMAIL: Illegal loan apps steal contacts/photos and harass. Do not install from links/APKs; check RBI-registered lenders only. Sextortion (nude video call recorded, then threat): do NOT pay (they keep asking), stop replying, block, save screenshots, report to 1930 and cybercrime.gov.in; use stopncii.org to stop intimate image spread; tell someone you trust; you are the victim, not at fault. Women/child helpline: 181/1098.'],
[/sim swap|sim block|sim card|sim.*(dead|no network)|number (blocked|disconnect)|trai|sanchar/i,'SIM/NUMBER SCAM: Callers claiming TRAI/telecom will disconnect your number are fake. Sudden loss of network signal + OTP alerts may be SIM swap: contact your operator at once and bank. Check numbers registered on your Aadhaar and report unknown ones at sancharsaathi.gov.in (TAFCOP).'],
[/olx|quikr|marketplace|buy|shopping|delivery|refund|courier|customer care|fake (support|number)|google search number/i,'ONLINE SHOPPING/OLX/CUSTOMER CARE: Scammers send "QR code to receive money", fake army-officer buyers, or fake customer-care numbers from Google. Never scan a QR or enter UPI PIN to receive money. Get customer-care numbers only from the official site/app. Prefer cash-on-delivery or trusted platforms; too-good-to-be-true prices are traps.'],
[/kyc|aadhaar|aadhar|pan card|electricity|bill|kyc update|link (aadhaar|pan)/i,'KYC/BILL SCAM: SMS like "KYC expired, click to update" or "electricity will be cut tonight" is fake. Banks and boards never ask KYC via link/WhatsApp/APK. Visit branch or official app. Lock Aadhaar biometrics on myaadhaar.uidai.gov.in if worried; never share Aadhaar OTP.'],
[/deepfake|ai voice|voice clone|fake video|relative.*(accident|emergency)|urgent money/i,'AI VOICE/DEEPFAKE SCAM: Scammers clone a relative\'s voice or face and ask for urgent money. Hang up and call the person back on their known number; agree a family safe-word; ask a personal question only they know; do not send money under pressure.'],
[/qr|scan qr|barcode/i,'QR SCAM: Scanning a QR is only for PAYING. If someone says scan QR to receive money, it is a scam. Check the merchant name shown before paying. Do not scan QR codes from random stickers/messages.'],
[/backup|data loss|recover file|cloud|storage/i,'BACKUP: Follow 3-2-1: 3 copies, 2 different media, 1 offsite/offline (external drive + cloud). Test restores. Encrypt backups; keep one copy disconnected so ransomware cannot reach it.'],
[/privacy|permission|tracking|location|camera|mic|app permission|delete data|data leak|breach/i,'PRIVACY: Review app permissions (location, mic, camera, contacts), remove unused apps, do not over-share on social media (birthday, address, tickets), use privacy settings, and check breaches at haveibeenpwned.com. After a breach: change passwords and enable 2FA.'],
[/child|kids|children|parent|cyberbullying|school|teen|game.*(scam|hack)/i,'KIDS SAFETY: Use parental controls, keep devices in shared spaces, talk openly, teach: never share photos/OTP/location with strangers, block and tell an adult about bullying or blackmail. Report child abuse content at cybercrime.gov.in; Childline 1098.'],
[/report|complaint|cybercrime|1930|fir|police station/i,'REPORTING (India): Call 1930 (financial fraud, act fast), file at cybercrime.gov.in (all cyber crimes, keep screenshots/txn IDs/numbers/URLs), tell your bank, and lodge FIR at the nearest police station/cyber cell if needed. Report scam numbers at sancharsaathi.gov.in (Chakshu).'],
[/email|gmail|outlook|attachment|invoice|spam|spoof|business email|bec/i,'EMAIL SAFETY: Check the real sender address, not the display name. Do not open unexpected attachments (.zip, .html, .exe, macro Office files). Invoices/bank-detail-change requests: verify by phone. Enable spam filter and 2FA; never log in from a link in an email.'],
[/antivirus|firewall|update|patch|windows defender|security tips|basic|hygiene|safe (browsing|internet)/i,'BASIC HYGIENE: keep OS/apps/browser updated, use Windows Defender or a reputable antivirus, enable firewall, avoid cracked software and unknown USBs, use standard (non-admin) accounts, install apps only from official stores, back up regularly, use a password manager with 2FA.']];
const FEW=[{role:'user',content:'Explain how to detect Kerberoasting in a SIEM.'},{role:'assistant',content:'Detect it by watching Kerberos service ticket requests (Event ID 4769) that use RC4 encryption (ticket encryption type 0x17) for non-computer service accounts, especially one user requesting many SPNs in a short time.\n1. Collect 4769 from all domain controllers into the SIEM.\n2. Alert when TicketEncryptionType=0x17 and ServiceName does not end with $.\n3. Add a threshold: more than 5 distinct ServiceName values from one account in 10 minutes.\n4. Respond: reset the targeted service account passwords (25+ random characters) or move them to gMSA.\nPro tip: enforce AES-only Kerberos so RC4 requests become high-fidelity alerts. Maps to MITRE ATT&CK T1558.003.'},{role:'user',content:'en phone-ku OTP share pannitten, ippo enna pannanum?'},{role:'assistant',content:'Bayapadaadheenga, udane action edutha safe-a irukkalaam.\n1. Ippove bank-ku call panni card/UPI block pannunga.\n2. 1930-ku call panni complaint pannunga (velaya seekiram pannanum).\n3. cybercrime.gov.in-la complaint podunga; screenshot, txn ID save pannunga.\nAdutha thadava: OTP, PIN, CVV yaarukkum share pannaadheenga, bank staff-ku kooda.'},{role:'user',content:'Is this SMS safe? "Your SBI KYC expires today, click sbi-kyc.xyz"'},{role:'assistant',content:'No, this is a phishing scam.\n1. Do not click the link or reply.\n2. SBI never asks for KYC through SMS links; the domain sbi-kyc.xyz is not official.\n3. If you already entered details, call your bank now and dial 1930.\nPrevention: use only the official SBI app or website.'}];
KNOW.push([/invest|trading|crypto|bitcoin|stock tip|double (your )?money|guaranteed return|telegram (group|channel)|forex/i,'INVESTMENT/CRYPTO SCAM: Guaranteed high returns, "double your money", Telegram/WhatsApp stock-tip groups and fake trading apps are scams. Real investments never guarantee returns. Check SEBI registration (sebi.gov.in) before investing. Never pay "tax/fees" to withdraw profits. If cheated: call 1930, file at cybercrime.gov.in, keep chats and txn IDs.'],[/job|task|part.?time|work from home|youtube like|telegram task|registration fee|offer letter|recruit/i,'JOB/TASK SCAM: Real employers never ask money for registration, training or "security deposit". Part-time "like videos / rate hotels for pay" Telegram tasks start with small payouts then demand big deposits. Verify company on its official site and LinkedIn; do not pay anything. Report to 1930 and cybercrime.gov.in.']);
const PRO=[
[/owasp|sql ?injection|sqli|\bxss\b|csrf|ssrf|idor|web ?(app|application)? ?(security|vuln)|broken access|injection attack/i,`WEB APP SECURITY (OWASP Top 10): broken access control (IDOR: enforce authorization server-side on every object), cryptographic failures, injection (SQLi -> parameterized queries; XSS -> output encoding + Content-Security-Policy; command injection -> avoid shell calls), insecure design, security misconfiguration, vulnerable components (keep dependencies updated, use SCA), auth failures (MFA, rate limiting, lockout), integrity failures, logging/monitoring gaps, SSRF (egress allow-list, block cloud metadata IP 169.254.169.254). Test only apps you own or have written permission for. Tools: Burp Suite, OWASP ZAP, DVWA/Juice Shop for practice.`],
[/mitre|att&ck|\bttps?\b|kill ?chain|threat model|\bstride\b|\bapt\b|threat intel|\bioc\b/i,`THREAT FRAMEWORKS: MITRE ATT&CK maps attacker tactics (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact) to techniques (T-IDs). Use it to build detections and gap-check coverage (ATT&CK Navigator). Lockheed Cyber Kill Chain = 7 stages. STRIDE for threat modeling: Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege. IOCs (hashes, IPs, domains) are short-lived; behavior-based TTP detections last longer.`],
[/incident response|\big\b|ir plan|breach response|containment|forensic|dfir|evidence|chain of custody|volatility|memory dump|disk image/i,`INCIDENT RESPONSE (NIST SP 800-61): 1 Preparation, 2 Detection and Analysis, 3 Containment-Eradication-Recovery, 4 Post-incident review. Do not power off a compromised machine before capturing volatile data (order of volatility: RAM, network state, processes, disk, logs). Image disks with a write blocker, hash with SHA-256, keep chain of custody, work only on copies. Tools: Autopsy, FTK Imager, Volatility, KAPE, Wireshark, Velociraptor. Isolate the host from the network (EDR isolate), reset exposed credentials, hunt for persistence, then write a timeline and lessons learned.`],
[/nmap|port scan|firewall|\bids\b|\bips\b|snort|suricata|segmentation|network (security|hardening)|\bdmz\b|vlan|wireshark|packet|tcpdump|zeek/i,`NETWORK SECURITY: default-deny firewall rules, segment networks (VLANs/DMZ), disable unused services, patch edge devices, use IDS/IPS (Suricata, Snort, Zeek) and review flow logs. Nmap basics on authorized targets only: nmap -sV -sC <host> (service/version + default scripts), nmap -p- <host> (all ports), -sS SYN scan needs root. Wireshark filters: ip.addr==x.x.x.x, tcp.port==443, http, dns. Detect scans by many SYNs to many ports from one source; detect beaconing by regular-interval outbound connections.`],
[/encrypt|hashing|\bhash\b|\baes\b|\brsa\b|\btls\b|\bssl\b|certificate|bcrypt|argon|\bsalt\b|cryptograph|\bpki\b|digital signature|\bhmac\b/i,`CRYPTOGRAPHY: symmetric AES-256-GCM (fast, same key); asymmetric RSA-2048+/ECC (key exchange, signatures); hashing SHA-256/SHA-3 for integrity (MD5 and SHA-1 are broken for security). Store passwords with Argon2id, bcrypt or scrypt + unique salt, never plain SHA. TLS 1.2+ only (prefer 1.3), valid certificates, HSTS. Encryption gives confidentiality, signatures/MACs give integrity and authenticity. Never invent your own crypto; use vetted libraries and keep keys in a KMS/HSM, not in code.`],
[/\baws\b|azure|\bgcp\b|cloud security|s3 bucket|\biam\b|kubernetes|\bk8s\b|docker|container security|misconfig/i,`CLOUD AND CONTAINER SECURITY: least-privilege IAM, MFA on root/admin, no long-lived access keys in code, block public S3/storage buckets, enable CloudTrail/Activity logs and GuardDuty/Defender, encrypt at rest and in transit, use security groups as default-deny. Containers: minimal base images, run as non-root, scan images (Trivy), no secrets in images, read-only filesystem, network policies in Kubernetes, restrict the Docker socket. Shared responsibility: provider secures the cloud, you secure what you put in it. Most cloud breaches come from misconfiguration and leaked keys.`],
[/pentest|penetration test|red team|ethical hack|bug bounty|\bctf\b|kali|metasploit|burp|recon|oscp|exploit/i,`PENTEST METHODOLOGY (authorized only): 1 scope + written authorization (rules of engagement), 2 recon (OSINT, DNS, subdomains), 3 scanning/enumeration (Nmap, service versions), 4 vulnerability analysis (Nessus/OpenVAS, manual validation), 5 exploitation inside scope, 6 post-exploitation and cleanup, 7 report with CVSS score, impact, proof, and fix. Legal note (India): unauthorized access is an offense under IT Act 2000 sections 43 and 66. Practice legally on TryHackMe, HackTheBox, VulnHub, DVWA, or your own VM lab. Bug bounty: stay inside program scope (HackerOne, Bugcrowd, Intigriti).`],
[/reverse engineer|malware analysis|sandbox|\byara\b|static analysis|dynamic analysis|ghidra|\bida\b|disassembl|unpack|suspicious (file|exe)/i,`MALWARE ANALYSIS (safe workflow): use an isolated VM with snapshots and no real network (or INetSim/FakeNet), never run samples on your main PC. Static: file hashes (check VirusTotal), strings, PE headers/imports (PEStudio, Detect It Easy), packers. Dynamic: Procmon, Process Hacker, Regshot, Wireshark, or sandboxes (CAPE, Any.Run). Reverse: Ghidra/IDA/x64dbg. Output: IOCs, behavior summary, YARA/Sigma detection rules. Defenders should block by behavior, not only hash.`],
[/\bsoc\b|siem|splunk|\belk\b|wazuh|\bedr\b|sigma rule|threat hunt|log analysis|detection engineering|\bxdr\b|qradar|sentinel/i,`SOC AND DETECTION: collect logs centrally (Windows Event, Sysmon, firewall, DNS, proxy, cloud audit) into a SIEM (Splunk, Elastic, Wazuh, Sentinel). Triage = validate, scope, classify severity, escalate. Good detections map to ATT&CK and are written as Sigma rules, tuned to cut false positives. Useful Windows Event IDs: 4624/4625 logon success/fail, 4672 special privileges, 4688 process creation, 4720 user created, 7045 service installed, 1102 log cleared. Hunt hypotheses: rare parent-child processes, PowerShell encoded commands, new scheduled tasks, unusual outbound beacons.`],
[/active directory|kerberos|\bntlm\b|domain controller|\bgpo\b|privilege escalation|lateral movement|mimikatz|pass.the.hash|kerberoast|bloodhound|\bladp\b/i,`ACTIVE DIRECTORY DEFENSE: tiered admin model (no domain admin logons on workstations), LAPS for local admin passwords, disable NTLM/SMBv1 where possible, SMB signing, add admins to Protected Users, long random passwords for service accounts or use gMSA (stops Kerberoasting), enable Credential Guard, rotate krbtgt twice after a breach. Monitor Event IDs 4768/4769 (Kerberos tickets, watch RC4 requests), 4776 (NTLM), 4672, 4728/4732 (group changes), DCSync indicators (replication requests from non-DC). Audit attack paths with BloodHound defensively.`],
[/linux|\bssh\b|\bsudo\b|hardening|selinux|apparmor|fail2ban|iptables|\bufw\b|\bcis benchmark/i,`LINUX HARDENING: keep packages updated, SSH key-only login (PasswordAuthentication no, PermitRootLogin no), change nothing relying on obscurity alone, firewall default-deny (ufw default deny incoming), fail2ban for brute force, least-privilege sudo, remove unused services (systemctl list-unit-files), enable auditd, SELinux/AppArmor enforcing, separate partitions with noexec where possible, file integrity checks (AIDE), follow CIS Benchmarks and scan with Lynis.`],
[/certification|career|roadmap|learn (cyber|hacking|security)|security\+|\bceh\b|\boscp\b|\bcissp\b|job in cyber|how to start (in )?cyber|beginner.*(hack|cyber|security)/i,`CYBER CAREER ROADMAP: 1 foundations: networking (TCP/IP, DNS, HTTP), Linux, Windows, basic Python/Bash. 2 entry cert: CompTIA Security+. 3 blue team: TryHackMe SOC path, LetsDefend, BTL1, CySA+. 4 red team: eJPT, PNPT, then OSCP. 5 cloud: AWS Security Specialty or AZ-500. 6 management: CISSP, CISM. Build a home lab, do CTFs, write blog/GitHub notes, and learn to write clear reports. Free practice: TryHackMe, HackTheBox, OverTheWire, PicoCTF, Blue Team Labs Online.`],
[/dpdp|cert-in|\bit act\b|compliance|iso ?27001|gdpr|pci.?dss|soc ?2|rbi (guideline|master)|audit|nist csf/i,`COMPLIANCE (India + global): IT Act 2000 (sections 43, 66, 66C identity theft, 66D cheating by impersonation, 67 obscene content). CERT-In directions 2022: report cyber incidents to CERT-In within 6 hours, keep system logs for 180 days, sync clocks to NTP. DPDP Act 2023 covers personal data: consent, purpose limitation, breach notification, data principal rights. ISO 27001 = ISMS certification; NIST CSF = Identify, Protect, Detect, Respond, Recover (and Govern); PCI DSS for card data; GDPR needs breach notice within 72 hours. Verify the latest rules on official sites before relying on them for legal decisions.`],
[/secure coding|devsecops|\bsast\b|\bdast\b|secrets? (leak|in (git|code))|api security|\bjwt\b|oauth|code review|dependency|supply chain|github (secret|security)|\.env/i,`SECURE CODING AND DEVSECOPS: validate input server-side, use parameterized queries, encode output, least privilege, fail closed. JWT: verify signature and algorithm (reject alg none), short expiry, keep secrets out of the payload, store the signing secret in env/secret manager. OAuth: use Authorization Code + PKCE, exact redirect_uri match, validate state. Never commit secrets (.env in .gitignore); if leaked, rotate immediately, removing the commit is not enough. Pipeline: Semgrep/CodeQL (SAST), Trivy/npm audit/Dependabot (SCA), gitleaks (secrets), ZAP (DAST). Pin dependencies and review third-party packages to reduce supply chain risk.`],
[/wpa2?|wpa3|evil twin|rogue ap|deauth|\bwps\b|wireless (security|attack)|router (security|hack)/i,`WIRELESS SECURITY: use WPA3 (or WPA2-AES) with a long passphrase, disable WPS, update router firmware, change default admin password, separate guest/IoT networks, disable remote admin. Evil twin and deauth attacks trick devices onto fake access points: do not accept unknown certificates, use a VPN on public Wi-Fi, and prefer WPA3/802.1X in organizations. Wireless testing is legal only on networks you own or are authorized to test.`],
[/zero trust|\bmfa\b|\b2fa\b|passkey|password manager|\bsso\b|phishing.?resistant|fido/i,`IDENTITY AND ZERO TRUST: never trust by network location, verify every user, device and request, give least privilege and re-check continuously. Prefer phishing-resistant MFA (passkeys/FIDO2, hardware keys) over SMS OTP; authenticator apps are better than SMS. Use a password manager with unique 14+ character passwords, SSO with conditional access, and review privileged accounts regularly.`]
];
KNOW.unshift(...PRO);
const ref=t=>{const m=KNOW.filter(k=>k[0].test(t)).slice(0,3);return m.length?'\n\nREFERENCE FACTS (use these, explain in the user\'s language):\n'+m.map(k=>'- '+k[1]).join('\n'):''};
const KB=KNOW;
/* ---------- Ollama AI Pro: auto model pick, low-RAM fallback, expert personas, streaming ---------- */
const OH=()=>E.OLLAMA_API_KEY?{authorization:'Bearer '+E.OLLAMA_API_KEY}:{};
const OL=()=>(E.OLLAMA_URL||'http://127.0.0.1:11434').replace(/\/+$/,'');
const LOCAL=()=>!E.OLLAMA_API_KEY&&/\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/i.test(OL());
const GB=1073741824,TOTAL=os.totalmem(),LOWRAM=TOTAL<8*GB,SMALL='gemma3:1b',TINY='gemma3:270m';
const NOTLLM=/embed|nomic|bge|minilm|mxbai|rerank/i;
const MEMERR=/alloc|memory|\bram\b|terminated|exit status|failed to load|unable to load|out of|killed|runner|cpu_repack|buffer/i;
const pick=(o,k,d)=>Object.prototype.hasOwnProperty.call(o,k)?o[k]:d;
const BAD=new Map();let LASTERR=null,TG={t:0,l:[]},PSC={t:0,s:new Set()},PULLING=false;
const jget=async(p,ms)=>(await fetch(OL()+p,{headers:OH(),signal:AbortSignal.timeout(ms||5000)})).json();
async function tags(){if(Date.now()-TG.t<15000&&TG.l.length)return TG.l;const j=await jget('/api/tags');TG={t:Date.now(),l:(j.models||[]).map(m=>({name:m.name,size:+m.size||0}))};return TG.l}
async function loadedSet(){if(Date.now()-PSC.t<5000)return PSC.s;try{PSC={t:Date.now(),s:new Set(((await jget('/api/ps',2500)).models||[]).map(m=>m.name))}}catch{PSC={t:Date.now(),s:new Set()}}return PSC.s}
const wantModel=()=>E.OLLAMA_MODEL&&E.OLLAMA_MODEL!=='auto'?E.OLLAMA_MODEL:'';
/* Ordered list of models to try. Local Ollama: the configured model first if it fits in free RAM, then the biggest model that fits, then the smallest ones as a last resort. A model that failed to load is skipped for 10 minutes (and every bigger model with it). */
async function candidates(){
 const want=wantModel();let list;
 try{list=(await tags()).filter(m=>!NOTLLM.test(m.name))}catch{throw new Error('Ollama not reachable at '+OL()+'. Start it with: ollama serve')}
 if(!list.length)throw new Error('No Ollama models installed. Run: ollama pull '+(want||SMALL));
 const has=n=>list.find(m=>m.name===n||m.name===n+':latest');
 if(!LOCAL()){const w=want&&has(want);return[w?w.name:list[0].name]}
 const now=Date.now(),loaded=await loadedSet(),free=os.freemem(),need=m=>m.size*1.25+.4*GB;
 const alive=list.filter(m=>!(BAD.get(m.name)>now-6e5)),pool=alive.length?alive:list;
 const possible=m=>!m.size||need(m)<TOTAL,fitsNow=m=>loaded.has(m.name)||!m.size||need(m)<=free;
 const w=want&&has(want),ord=[],add=m=>{if(m&&!ord.includes(m.name))ord.push(m.name)};
 if(w&&pool.includes(w)&&fitsNow(w)&&possible(w))add(w);
 pool.filter(m=>fitsNow(m)&&possible(m)).sort((a,b)=>b.size-a.size).forEach(add);
 pool.slice().sort((a,b)=>a.size-b.size).forEach(add);
 return ord}
function markBad(name){const m=TG.l.find(x=>x.name===name),sz=m?m.size:0,t=Date.now();BAD.set(name,t);if(sz)TG.l.forEach(x=>{if(x.size>=sz)BAD.set(x.name,t)})}
async function aiHealth(){try{const c=await candidates(),want=wantModel(),bad=LOCAL()&&BAD.get(c[0])>Date.now()-6e5,pl=PULLING?{name:PULLP.name,pct:PULLP.pct}:undefined;
 return{up:!bad,model:c[0],fallback:!!want&&c[0]!==want&&c[0]!==want+':latest',ramGB:+(TOTAL/GB).toFixed(1),freeGB:+(os.freemem()/GB).toFixed(1),pulling:pl,warn:LASTERR&&Date.now()-LASTERR.t<6e5?LASTERR.m:undefined,error:bad?(pl?'Downloading small AI model '+pl.pct+'%':'Model does not fit in RAM; a small model is needed (gemma3:1b)'):undefined,url:OL().replace(/\/\/[^@/]*@/,'//')}}catch(e){return{up:false,error:e.message}}}
let PULLP={name:'',pct:0};
async function pullModel(name){
 const r=await fetch(OL()+'/api/pull',{method:'POST',headers:{'content-type':'application/json',...OH()},body:JSON.stringify({model:name,stream:true})});
 if(!r.ok)throw new Error('pull HTTP '+r.status);
 PULLP={name,pct:0};const td=new TextDecoder();let buf='',ok=false;
 const line=l=>{if(!l)return;let j;try{j=JSON.parse(l)}catch{return}if(j.error)throw new Error(j.error);if(j.total&&j.completed)PULLP.pct=Math.min(99,Math.round(100*j.completed/j.total));if(j.status==='success')ok=true};
 for await(const c of r.body){buf+=td.decode(c,{stream:true});let k;while((k=buf.indexOf('\n'))>=0){line(buf.slice(0,k).trim());buf=buf.slice(k+1)}}
 line(buf.trim());return ok}
/* Downloads a tiny safety-net model in the background (ON by default; set OLLAMA_AUTOPULL=never to disable). Skipped if a small model is already installed. */
async function autoPull(){
 if(PULLING||!LOCAL()||/^(never|off|no|false)$/i.test(E.OLLAMA_AUTOPULL||''))return;
 PULLING=true;
 try{
  TG.t=0;const have=(await tags()).some(m=>m.size&&m.size<1.6*GB&&!NOTLLM.test(m.name));
  if(!have){for(const name of [SMALL,TINY]){console.log('[ai] downloading small model '+name+' ...');
    try{if(await pullModel(name)){console.log('[ai] '+name+' ready');break}}catch(e){console.log('[ai] download of '+name+' failed:',e.message)}}}
 }catch(e){console.log('[ai] auto-download skipped:',e.message)}
 PULLING=false;PULLP={name:'',pct:0};TG.t=0}
/* ---------- Prompts: pro system prompt + expert personas + answer length per mode ---------- */
const SYSP=`You are CyberShield AI Pro, an expert-level cyber security assistant: SOC/blue team, DFIR, authorized pentesting, network, cloud, web/app security, cryptography, malware analysis, compliance, and everyday scam/fraud help for people in India.
Answer every legitimate cyber security question directly and completely, from beginner to professional, however it is phrased (Tamil, Tanglish, English, short or messy). Match depth to the user: beginners get simple words and steps; professionals get precise detail, commands, configs, detection ideas and references (MITRE ATT&CK, OWASP, NIST, CVE).
LANGUAGE: copy the user's language. Tanglish -> natural simple Tanglish; Tamil script -> Tamil; English -> English. Keep technical terms (OTP, phishing, firewall, SIEM...) in English.
FORMAT: start with a 1-line direct answer, then numbered steps, then a short "Pro tip:" when useful. Put every command or code in a fenced code block. Use **bold** only for key terms. No headings.
INDIA: cybercrime helpline 1930, cybercrime.gov.in, call the bank at once to block card/UPI, sancharsaathi.gov.in for SIM issues, CERT-In for incidents.
SAFETY: explain attacks so people can defend; hands-on work assumes the user's own lab or written authorization. No ready-to-use malware, ransomware, stalkerware, phishing kits, credential theft tools, or step-by-step attacks on a named real person/system; offer the defensive alternative.
HONESTY: never invent facts, CVE numbers, commands or flags; say "I am not sure" and how to verify. Prefer the REFERENCE FACTS when given. If the question is not about security/IT, say so in one line and steer to a security angle.`;
const PERSONA={general:'',
 scam:'FOCUS: everyday scam and fraud help for non-technical people. Be calm and reassuring. Put the most urgent action first (call 1930, block card/UPI). Keep steps short and simple.',
 soc:'FOCUS: SOC analyst / blue team. Give detections (Windows Event IDs, Sysmon, Sigma/KQL/SPL ideas), triage steps, MITRE ATT&CK technique IDs and containment actions.',
 red:'FOCUS: authorized penetration testing, CTF and lab work. Assume written authorization or the user\'s own lab (mention scope once). Give methodology, enumeration commands, and the defensive fix for each finding. No weaponized malware and no attacks on named real targets.',
 dfir:'FOCUS: DFIR and malware analysis: evidence preservation, order of volatility, triage commands, timeline building, safe sandbox analysis, and IOC/YARA/Sigma outputs.',
 cloud:'FOCUS: cloud, container and DevSecOps security: IAM least privilege, misconfiguration checks, logging, IaC and CI/CD pipeline security, secrets handling, with concrete CLI/config examples.'};
const LEN={fast:'LENGTH: be brief, under 120 words.',balanced:'LENGTH: focused answer, about 200 words.',deep:'LENGTH: be thorough and structured: why it works, step-by-step, commands, detection, prevention, common mistakes, references.'};
const MODES={fast:{n:350,c:3072,t:'low'},balanced:{n:700,c:4096,t:'low'},deep:{n:1400,c:6144,t:'medium'}};
/* rank reference facts by how many times their pattern matches, not just by order */
const refs=(t,n)=>KNOW.map((k,i)=>{const m=t.match(new RegExp(k[0].source,'gi'));return[m?m.length:0,i,k[1]]}).filter(x=>x[0]).sort((a,b)=>b[0]-a[0]||a[1]-b[1]).slice(0,n);
const facts=(t,n,max)=>{const r=refs(t,n);return r.length?'\nREFERENCE FACTS (trusted; explain in the user\'s language):\n'+r.map(x=>'- '+x[2].slice(0,max)).join('\n'):''};
function cleanHist(h){const msgs=[];for(const x of h){const r=x.r==='u'?'user':'assistant';if(!msgs.length&&r!=='user')continue;if(msgs.length&&msgs[msgs.length-1].role===r)msgs[msgs.length-1].content+='\n'+x.t;else msgs.push({role:r,content:String(x.t||'').slice(0,r==='user'?1800:900)})}return msgs}
/* one streamed call to one model */
async function callModel(model,build,msgs,MD,signal,onTok,tiny){
 const gpt=/gpt-oss/i.test(model),LOW=LOCAL()&&(LOWRAM||os.freemem()<3*GB),ctx=tiny?1024:LOW?Math.min(MD.c,MD.n>1000?3072:2048):MD.c;
 for(const think of [gpt?MD.t:false,undefined]){
  const r=await fetch(OL()+'/api/chat',{method:'POST',headers:{'content-type':'application/json',...OH()},body:JSON.stringify({model,stream:true,think,keep_alive:'30m',messages:[{role:'system',content:build(ctx)},...(ctx>=4096?FEW:[]),...msgs],options:{num_predict:tiny?Math.min(MD.n,400):MD.n,temperature:.3,top_p:.9,repeat_penalty:1.08,num_ctx:ctx,...(tiny?{num_batch:32}:LOW?{num_batch:128}:{})}}),signal});
  if(!r.ok){const j=await r.json().catch(()=>({})),er=j.error||'Ollama error '+r.status;if(think===false&&/think/i.test(er))continue;throw new Error(er)}
  const td=new TextDecoder();let buf='',got=false;
  const line=l=>{if(!l)return;let j;try{j=JSON.parse(l)}catch{return}if(j.error)throw new Error(j.error);const c=j.message&&j.message.content;if(c){got=true;onTok(c)}};
  for await(const c of r.body){buf+=td.decode(c,{stream:true});let i;while((i=buf.indexOf('\n'))>=0){line(buf.slice(0,i).trim());buf=buf.slice(i+1)}}
  line(buf.trim());return got}}
/* generate: tries the best model, and if it cannot load (not enough RAM) silently falls back to a smaller one */
async function generate({h,mode,persona,signal,onTok}){
 const msgs=cleanHist(h);if(!msgs.length||msgs[msgs.length-1].role!=='user')throw new Error('Empty message');
 const MD=pick(MODES,mode,MODES.fast),lastU=msgs.filter(m=>m.role==='user').slice(-2).map(m=>m.content).join(' ');
 const build=ctx=>SYSP+'\n'+pick(PERSONA,persona,'')+'\n'+pick(LEN,mode,LEN.fast)+facts(lastU,ctx>=4096?3:2,ctx>=4096?700:450);
 const names=await candidates();let lastErr,tries=0;
 for(const name of names){if(tries++>=3)break;const mm=TG.l.find(x=>x.name===name),smallish=!!(mm&&mm.size&&mm.size<1.6*GB);
  for(const tiny of [false,true]){let sent=false;
   try{const got=await callModel(name,build,msgs,MD,signal,t=>{sent=true;onTok(t)},tiny);if(!got)onTok('(empty reply)');LASTERR=null;return name}
   catch(e){if(signal.aborted)throw e;if(e instanceof TypeError){TG.t=0;throw new Error('Ollama not reachable at '+OL()+'. Start it with: ollama serve')}lastErr=e;if(sent)throw e;
    if(LOCAL()&&MEMERR.test(e.message||'')){LASTERR={t:Date.now(),m:String(e.message).slice(0,200)};
     if(!tiny&&smallish){console.log('[ai] '+name+' failed ('+String(e.message).slice(0,70)+') -> retrying with tiny settings');continue}
     markBad(name);console.log('[ai] '+name+' could not load ('+String(e.message).slice(0,90)+') -> trying a smaller model');break}
    throw e}}}
 if(lastErr&&LOCAL()&&MEMERR.test(lastErr.message||''))autoPull();
 throw lastErr||new Error('No usable model')}
const friendly=e=>{const m=String(e&&e.message||e);if(e&&e.name==='AbortError')return'AI romba neram eduthuchu (timeout). Fast mode use pannunga, illa smaller model use pannunga.';
 if(MEMERR.test(m)&&!/not reachable|No Ollama models/.test(m)){console.log('[ai] reply failed (RAM):',m.slice(0,220));
  return PULLING?'AI chinna model ('+(PULLP.name||SMALL)+') download aagudhu: '+PULLP.pct+'%. 2-5 nimisham la ready aagidum, apram thirumba kelunga. Adhuvarai mela irukkura built-in guide answer-ah paarunga.':'Indha PC-la RAM kammi, adhaala periya AI model load aagala. Chinna model ('+SMALL+') thaanaaga download aagum, konjam neram kazhichu thirumba kelunga. (Illa: setup-ai.bat run pannunga.)'}
 return m}
const offlineReply=(h,x)=>{const k=refs(String((h[h.length-1]||{}).t||''),2);return(k.length?'📚 Offline guide (built-in knowledge):\n'+k.map(y=>y[2]).join('\n\n')+'\n\n':'')+'⏳ AI engine: '+friendly(x)};
async function streamChat(req,res,h,mode,persona){
 const ac=new AbortController(),to=setTimeout(()=>ac.abort(),18e4);res.on('close',()=>{ac.abort();clearTimeout(to)});
 res.writeHead(200,{'content-type':'text/plain; charset=utf-8','cache-control':'no-store','x-accel-buffering':'no'});req.socket.setNoDelay(true);res.flushHeaders&&res.flushHeaders();
 let sent=false;try{await generate({h,mode,persona,signal:ac.signal,onTok:t=>{sent=true;res.write(t)}})}
 catch(x){if(!res.destroyed)res.write((sent?'\n\n':'')+offlineReply(h,x))}
 clearTimeout(to);res.end()}
/* ---------- helpers ---------- */
const hits=new Map();const limited=(ip,max=12)=>{const n=Date.now(),a=(hits.get(ip)||[]).filter(t=>n-t<6e4);a.push(n);hits.set(ip,a);return a.length>max};
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript','.json':'application/json','.svg':'image/svg+xml','.css':'text/css','.png':'image/png','.ico':'image/x-icon'};
const body=req=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>2e5){no(0);req.destroy()}});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{ok({})}})});
const send=(res,c,o)=>{res.writeHead(c,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(o))};
const mkUser=d=>({...d,joined:Date.now(),scans:0,done:[]});
const UC=new Map();const gu=async e=>{const c=UC.get(e);if(c&&Date.now()-c.t<30000)return c.u;const u=await store.get(e);if(u)UC.set(e,{u,t:Date.now()});return u};
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');
 const og=req.headers.origin;if(og&&/^(null|https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?)$/.test(og)){res.setHeader('Access-Control-Allow-Origin',og);res.setHeader('Access-Control-Allow-Headers','authorization,content-type');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');res.setHeader('Vary','Origin')}
 if(req.method==='OPTIONS'){res.writeHead(204);return res.end()}
 if(req.headers['x-forwarded-proto']==='https')res.setHeader('Strict-Transport-Security','max-age=31536000');
 const url=new URL(req.url,'http://x');
 if(!url.pathname.startsWith('/api/')){const root=path.join(__dirname,'public');let f=path.normalize(path.join(root,url.pathname==='/'?'index.html':url.pathname));if(!f.startsWith(root)||!fs.existsSync(f)||fs.statSync(f).isDirectory()){res.writeHead(404);return res.end('Not found')}res.writeHead(200,{'content-type':MIME[path.extname(f)]||'application/octet-stream','cache-control':'no-cache'});return fs.createReadStream(f).pipe(res)}
 try{if(url.pathname==='/api/ping')return send(res,200,{ok:1});await Promise.race([READY,new Promise(r=>setTimeout(r,20000))]);if(!store)return send(res,503,{error:'Database is starting, retry in a few seconds.'});const b=await body(req),p=url.pathname,ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim();
  if(p==='/api/ping')return send(res,200,{ok:1});
  if(p==='/api/health')return send(res,200,{ok:1,v:'6.4',db:store.kind,ai:await aiHealth()});
  if(p==='/api/signup'&&req.method==='POST'){if(limited(ip))return send(res,429,{error:'Too many attempts. Wait a minute.'});
   const e=String(b.email||'').trim().toLowerCase(),n=String(b.name||'').trim().slice(0,60),pw=String(b.password||'');
   if(!/^\S+@\S+\.\S+$/.test(e)||pw.length<8||!n)return send(res,400,{error:'Invalid name, email or password (min 8).'});
   if(await store.get(e))return send(res,409,{error:'Account already exists. Sign in.'});
   const salt=crypto.randomBytes(16).toString('hex'),u=mkUser({email:e,name:n,phone:'',salt,hash:hpw(pw,salt)});await store.add(u);return send(res,200,{token:sign(e),user:pub(u)})}
  if(p==='/api/login'&&req.method==='POST'){if(limited(ip))return send(res,429,{error:'Too many attempts. Wait a minute.'});
   const e=String(b.email||'').trim().toLowerCase(),u=await store.get(e);
   if(!u||!crypto.timingSafeEqual(Buffer.from(hpw(String(b.password||''),u.salt)),Buffer.from(u.hash)))return send(res,401,{error:'Wrong email or password.'});return send(res,200,{token:sign(e),user:pub(u)})}
  const em=verify((req.headers.authorization||'').replace('Bearer ','')),u=em&&await gu(em);if(!u)return send(res,401,{error:'Please sign in again.'});
  if(p==='/api/me'){if(req.method==='GET')return send(res,200,{user:pub(u)});
   if(req.method==='PUT'){if(typeof b.name==='string'&&b.name.trim())u.name=b.name.trim().slice(0,60);if(Number.isInteger(b.scans)&&b.scans>=u.scans)u.scans=b.scans;if(Array.isArray(b.done))u.done=[...new Set(b.done.filter(x=>Number.isInteger(x)&&x>=0&&x<50))];await store.upd(u);return send(res,200,{user:pub(u)})}
   if(req.method==='DELETE'){await store.del(em);UC.delete(em);return send(res,200,{ok:1})}}
  if(p==='/api/log'&&req.method==='POST'){await store.log(em,String(b.type||'').slice(0,40),Math.max(0,Math.min(100,+b.score||0)));return send(res,200,{ok:1})}
  if(p==='/api/history')return send(res,200,{items:await store.hist(em)});
  if(p==='/api/chat'&&req.method==='POST'){if(limited('c'+em,25))return send(res,429,{error:'Too many messages, wait a minute.'});const h=Array.isArray(b.history)?b.history.slice(-6):[],mode=String(b.mode||'fast'),persona=String(b.persona||'general').slice(0,12);
   if(b.stream)return streamChat(req,res,h,mode,persona);
   let out='';try{const model=await generate({h,mode,persona,signal:AbortSignal.timeout(18e4),onTok:t=>out+=t});return send(res,200,{reply:out.trim(),model})}catch(x){return send(res,200,{offline:1,reply:offlineReply(h,x)})}}
  send(res,404,{error:'Not found'})}catch(x){console.error('[ERROR]',req.method,url.pathname,'->',x&&x.message||x);send(res,500,{error:'Server error'+(PROD?'':': '+(x&&x.message||''))})}
});
server.on('error',e=>{console.error(e.code==='EADDRINUSE'?'\n*** PORT '+PORT+' already in use: an OLD CyberShield is still running. Close its window (or run: taskkill /F /IM node.exe) and start again. ***':e);process.exit(1)});
const READY=initStore().then(()=>console.log('[db] ready: '+store.kind)).catch(e=>console.error('[db] init failed',e));
server.listen(PORT,HOST,()=>console.log('\n  >>> OPEN IN BROWSER:  http://localhost:'+PORT+'  <<<\nCyberShield AI Pro running on port '+PORT+' | Ollama: '+OL()+' | model: '+(wantModel()||'auto')+' | RAM: '+(TOTAL/GB).toFixed(1)+' GB'+(LOWRAM?' (low-RAM mode)':'')));
/* preload the best model that actually loads (falls back to smaller ones when RAM is short) */
setTimeout(async()=>{if(!LOCAL())return;try{autoPull();for(const m of(await candidates()).slice(0,3)){const r=await fetch(OL()+'/api/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({model:m,messages:[],keep_alive:'30m'})}),j=await r.json().catch(()=>({}));if(r.ok&&!j.error){console.log('[ai] model preloaded: '+m);return}console.log('[ai] '+m+' failed to load: '+String(j.error||r.status).slice(0,120));if(MEMERR.test(j.error||''))markBad(m);else break}autoPull()}catch{}},2500);
process.on('uncaughtException',e=>console.error('[ERROR-kept-running]',e));process.on('unhandledRejection',e=>console.error('[REJECTION]',e));
