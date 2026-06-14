# Splunk Integration Development
- With the setup finished, this part details the about the building the Python bridge inside my `mitre-sigma-lookup-tool` project to translate the Sigma rules and push them directly over the network 

## Updating the `.env` file
- First, I had to update the `.env` file. This was to add a new Splunk VM connection detail so the script knows where to send the data to. Obviously, I can't show you this but for placeholder purposes, below are the values you need to fill in except the port, everyone knows that one
```python
SPLUNK_HOST=[Proxmox Ubuntu IP address goes here]
SPLUNK_PORT=8089        
SPLUNK_USER=[Your Splunk username here]
SPLUNK_PASSWORD=[Your Splunk password here]
```

## Install the required libraries
- Make sure you are in your virtual environment (`venv`) and activated and these are the libraries required to compile Sigma rules and communicate with the Splunk API
```bash
pip install splunk-sdk pysigma pysigma-backend-splunk
```
- where `splunk-sdk` handles the authenticated networking tunnel to the Proxmox VM and `pysigma` and `pysigma-backend-splunk` are python compilation framework that transforms Sigma YAML directly into Splunk SPL strings

- Then I added the code logic (see `mitre-attack-sigma.py` file). The flow is detailed below in a nice detailed diagram

## SIEM Architecture Diagram
<img width="1247" height="694" alt="image" src="https://github.com/user-attachments/assets/a226bc4d-df83-4277-9a1c-1c77d1cece8c" />

## Demo
- For demo purposes, I chose the `T1003` ATT&CK ID (OS Credential Dumping). I ran the command `mitre T1003` and hit `y` when asked

<img width="1246" height="546" alt="image" src="https://github.com/user-attachments/assets/9b3a239a-1c64-42df-b64d-59ab501042ed" />

- Then, it gives me a selection choice of the Sigma rules I could choose from. Here, I picked `118`

<img width="1194" height="604" alt="image" src="https://github.com/user-attachments/assets/0e9581aa-5f68-4261-a7fd-40cf617aa983" />

- As we can see, it worked successfully

<img width="3128" height="936" alt="image" src="https://github.com/user-attachments/assets/d785d93d-6c65-4c82-a80b-fe5be0f5ed9d" />

- If we navigate to `Splunk` > `Settings` (Gear Icon) > `Searches, reports and alerts`, we see the deployed rule

<img width="1512" height="310" alt="image" src="https://github.com/user-attachments/assets/73872e61-3b23-4a36-a3e5-7dd512a62980" />

- If we click on `Edit`, we can see that SPL Query itself

<img width="1512" height="586" alt="image" src="https://github.com/user-attachments/assets/07bfe985-3b00-4fe5-bf64-c86e7022a9c0" />
