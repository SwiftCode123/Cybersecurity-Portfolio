## Post Project Implmentation #1: Alias
- I decided to add this improvement as the first one. Creating an alias is very helpful instead of typing out long commands in the terminal
	- To make it a standalone command, we need to give the file execute permissions. This is because Unix systems require execute permissions before a script 	  can be run directly from the terminal
 ```bash
chmod +x mitre-attack-sigma.py
```
 - Next, I was in my virtual environment, `venv` and ran the command below.   Since I am in a 	virtual environment and my 		script relies on packages such as `rich` and `yaml` inside my `venv`, a standard alias 		might fail if the virtual environment isn't active and this command fixes that issue
```bash
echo "alias mitre=\"\$(pwd)/venv/bin/python3 \$(pwd)/mitre-attack-sigma.py\"" >> ~/.zshrc
```
- Run this to apply the changes
```bash
source ~/.zshrc
```

  - As you can see instead of having to `cd` inside folders and provide a long command, I can just type `mitre` which is the alias and it works the same way as it did before. Note that I also do not need to be inside the `venv` folder and can deactivate it and it still works
<img width="5192" height="6508" alt="image" src="https://github.com/user-attachments/assets/afff9932-114d-4515-b1d2-c543568f4c9d" />
