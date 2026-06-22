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
<img width="1015" height="702" alt="image" src="https://github.com/user-attachments/assets/721c7c86-6256-4f2e-99e3-0f85e17ef881" />


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

- Now, I made some changes to the code to turn the scheduled search into an active, firing alert that does something when a rule is triggered

```python
service.saved_searches.create(
                name=clean_title,
                search=splunk_spl,
                **{
                    "is_scheduled": "1",
                    "cron_schedule": "*/5 * * * *",
                    "alert_type": "number of events",
                    "alert_threshold": "0",
                    "alert_comparator": "greater than",
                    "actions": "webhook", 
                    "action.webhook.param.url": "https://httpbin.org/post"
                }
            )
```
- Now the thing is because our Splunk VM does not have live Windows event logs streaming into it, running the query above returns 0 events and so Splunk wouldn't trigger the alarm. To get a real test, I changed the above query to this
```
index=_internal group=per_sourcetype_thruput
```
<img width="1506" height="803" alt="image" src="https://github.com/user-attachments/assets/b05edd49-931f-4d8c-aa33-5392a0f093b0" />

- Then, I clicked `Run` and typed in the query which returned over 4,000 results

<img width="1512" height="824" alt="image" src="https://github.com/user-attachments/assets/3a85eb2c-de7b-4d5d-bc77-1bbe12a71069" />

- I clicked `Save` and note that the alert is no longer detecting the original threat and it’s now just watching internal Splunk activity

<img width="1512" height="829" alt="image" src="https://github.com/user-attachments/assets/7f00016e-0895-4734-8067-71c40f163315" />

- If we click `Search` on the left side and type in the query, we can see that the Splunk is firing the alerts every 5 minutes like we specified

<img width="1195" height="657" alt="image" src="https://github.com/user-attachments/assets/b020fae9-eeca-44db-96b8-21d8b5dc65c5" />

- If we specifically look at these 4 logs, we know what's happening

<img width="983" height="359" alt="image" src="https://github.com/user-attachments/assets/a09a912f-4007-4d68-a505-2b9e7b76d813" />

```
Invoking modular alert action=webhook for search="SIGMA - Lsass Memory Dump via Comsvcs DLL"
```
- This log specifies that Splunk Scheduler looked at the custom rule and since it matches more than 0 events, it successfully grabbed the webhook trigger instructions the Python script deployed (it ran the alert action which was the webhook)

```
Sending POST request to url=https://httpbin.org/post with size=2520 bytes payload
```
- Splunk packaged the alert metadata into a 2.5 KB JSON payload and sent it over the internet to the webhook URL (`https://httpbin.org/post`)

```
Webhook receiver responded with HTTP status=200
```
- The public test server caught the packet, accepted it, and sent a `200 OK` status back to the Proxmox VM

```
Alert action script completed... with exit code=0
exit code=0
```
- This last line indicated that the alert action script was compeleted successfully with no errors

## Splunk App
This addition extends the project by introducing a Splunk App Factory mode. Instead of deploying individual detections through the Splunk API, the tool can now compile all matched Sigma rules into a complete Splunk application, including scheduled searches, alerts, and a monitoring dashboard. The generated content is automatically packaged into a `.spl` file, allowing the entire detection set to be imported into Splunk through the App Management interface in a single step (see `mitre-attack-sigma.py` for such changes)

### Demo
```bash
mitre T1555 -o my_test_results
```

<img width="4164" height="1176" alt="image" src="https://github.com/user-attachments/assets/6f53d111-c0d6-46bf-8ed2-f7f57180ecd8" />

- I clicked `Manage` on the main menu under `Apps` and then clicked `Install App From File` to upload my `.spl` file

<img width="1141" height="598" alt="image" src="https://github.com/user-attachments/assets/05ee203a-d673-418a-bc09-75144f017e24" />

- We see the success message

<img width="1512" height="827" alt="image" src="https://github.com/user-attachments/assets/0b9aaa40-4a99-4e2b-b5ec-80d2b7b7e092" />
