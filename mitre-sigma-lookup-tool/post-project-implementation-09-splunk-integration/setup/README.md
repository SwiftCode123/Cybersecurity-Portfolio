# Splunk Integration Setup
- This part details the setup of the Splunk integration. Note that I already have Promox installed on my Windows computer and so I was able to do everything through my Proxmox web console on my Macbook

## Download the Ubuntu Server ISO
- Go the `https://ubuntu.com/download/server` and click `Download` for the latest Ubuntu Server. For me, I downloaded Ubuntu Server 26.04 LTS

<img width="1041" height="589" alt="image" src="https://github.com/user-attachments/assets/87eaa583-7f1f-4d2a-a26a-2c19dfc39c03" />

- I went to my Proxmox web console, expanded the storage node on the left, and clicked on local (`1`). I then selected the ISO Images tab in the center menu (`2`) and clicked `Upload` (`3`) and then `Select File` (`4`) to upload the Ubuntu ISO

<img width="1343" height="578" alt="image" src="https://github.com/user-attachments/assets/14db734e-4beb-483c-8da8-64ffac2c991f" />

## Create the Splunk Virtual Machine
- Click `Create VM` at the top right corner

<img width="1348" height="585" alt="image" src="https://github.com/user-attachments/assets/2996dbef-2d41-48a7-b376-6d6cb8a82766" />

- Once you click `Create VM`, this menu should popup. For this first one, name your VM. I choose `splunk-server-vm` for simplicity

<p align="center">
<img width="920" height="687" alt="image" src="https://github.com/user-attachments/assets/12af2c71-688f-47ba-9249-45f24f27a102" />
</p>

- After you click `Next`, select your Ubuntu ISO that you downloaded. For the `System` tab after this tab, I personally skipped and left it on default because there was no change needed

<p align="center">
<img width="906" height="680" alt="image" src="https://github.com/user-attachments/assets/f30393ed-ede6-4773-b0e2-0b2f0e8cbe17" />
</p>

- Then, set the Disk Size to 40-50 GiB. I picked 50 GB but this depends on your setup

<p align="center">
<img width="873" height="654" alt="image" src="https://github.com/user-attachments/assets/216d1679-787c-4972-9491-45e06d41cabc" />
</p>

- Set the Cores to 2 or 4 (depending on the level of computational performance on your secondary machine's CPU)

<p align="center">
<img width="831" height="620" alt="image" src="https://github.com/user-attachments/assets/34a60d12-1bd6-46eb-9740-858ce386bdc4" />
</p>

- Set the memory to 4 or 8 GB (depends on your setup and how much RAM you have). For the `Network` tab, I also skipped this one and left it on default and clicked `Finish` after this to setup the VM

<p align="center">
<img width="809" height="604" alt="image" src="https://github.com/user-attachments/assets/b6663947-f59e-421d-83cc-953902d5eb77" />
</p>

## Install the Ubuntu OS
- Click on your VM (`1`) and then Console (`2`) and then click on the `Start Now` button (`3`)

<img width="1394" height="536" alt="image" src="https://github.com/user-attachments/assets/eb3aed70-a65c-472c-86db-bc962b0a6132" />

- Click the below option

<p align="center">
<img width="608" height="336" alt="image" src="https://github.com/user-attachments/assets/d9ff9c76-04d8-46a6-a9b0-c42599c655f6" />
</p>

- Select your preferred language and keyboard layout (next option)

<p align="center">
<img width="605" height="379" alt="image" src="https://github.com/user-attachments/assets/d5c624d9-82b1-4ddb-a1df-afc377f38f9d" />
</p>

- Click the default option (first option)
<p align="center">
<img width="605" height="378" alt="image" src="https://github.com/user-attachments/assets/a453db5f-8cc4-4ae8-bd27-a6b1cebdda73" />
</p>

- It will automatically grab an IP address via DHCP. Write down this IP address as we will use this later
<p align="center">
<img width="606" height="377" alt="image" src="https://github.com/user-attachments/assets/6094e337-86d4-47b0-a108-205a9f5b0cc5" />
</p>

- Click `Use an entire disk`
<p align="center">
<img width="617" height="383" alt="image" src="https://github.com/user-attachments/assets/b0ad5547-a2a6-454e-8b2c-240114eb3e56" />
</p>

- Enter the below information
<p align="center">
<img width="574" height="359" alt="image" src="https://github.com/user-attachments/assets/1dd991ac-4b0c-4069-bd33-807a5011e315" />
</p>

- Click `Install OpenSSH server` and I used this to SSH from my Macbook instead of having to use the Proxmox browser (Note that we also needed the IP address from the previous step). For the next step, just click through the optional featured snaps screen and wait for installation
<p align="center">
<img width="574" height="358" alt="image" src="https://github.com/user-attachments/assets/ee594ba4-31a9-42ab-8a0b-51d4e56a35af" />
</p>

- Wait until this completes and click `Reboot` when finished. Note that if Proxmox asks you to remove the installation medium, just hit enter

<p align="center">
<img width="573" height="359" alt="image" src="https://github.com/user-attachments/assets/5c463290-fd95-4a41-b074-09e3035232b1" />
</p>

## Verify the Remote Connection
- Once the VM boots back up, I used my terminal on my Macbook to SSH directly into the VM and was successfully able to login
```bash
ssh username_goes_here@<VM_IP_ADDRESS_GOES_HERE>
```
## Splunk Enterprise SIEM engine setup
- Now that we are done with the Ubuntu installation and were able to SSH inside the VM, we now need to install and configure the Splunk Enterprise SIEM engine

### 1. Install `wget`
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install wget -y
```
- This was to ensure packet manager was up to date and that we have `wget` installed so we can pull down the installer package. I ran this inside my Proxmox VM

### 2. Download the Splunk Enterprise Package
```bash
wget -O splunk-10.4.0-f798d4d49089-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/10.4.0/linux/splunk-10.4.0-f798d4d49089-linux-amd64.deb"
```
### 3. Install the package
```bash
sudo dpkg -i splunk-10.4.0-f798d4d49089-linux-amd64.deb
```

### 4. Start the SIEM Engine
```bash
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
```
- After these steps, enter your administrator username and password. Once this is done, the SIEM will be live. Note that it will give you a link to go to

<img width="1508" height="852" alt="image" src="https://github.com/user-attachments/assets/2a5a8aae-7cac-4cf4-9bae-64c313e6ab11" />

- Enter your administrator username and password that you just created and BOOM, we are in!
- We have finally completed the whole setup process and look at that clean dashboard :D

<img width="1512" height="864" alt="image" src="https://github.com/user-attachments/assets/24c14d76-b78d-4f31-ae9f-721233722b5f" />
