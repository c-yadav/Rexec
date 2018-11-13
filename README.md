# Rexec
Program to execute a given script against a list of hosts

- Rexec.jar is an executable jar file. 
- It executes a given script against a list of hosts for you, there's no need to setup user equivalence for your user for each of the hosts.
- It requires a user ID with same credentials on each of the hosts e.g. an AD account.
- Rexec program supports execution of script on remote host with user having sudo privilege. If your's user ID is an unprivilege one and the script requires privilege user for execution and your user ID has sudo privilege, then you can provide the sudo user ID for script execution. 
- The output of script execution from each of the hosts will be redirected on STDOUT.

# Usage
`$ java -jar Rexec.jar -help`
- `-o <optional_args>`      arguments that will be passed to script file.  
- `-p <parallel_threads>`   number of threads to process remote hosts in parallel, default 4.  
- `-r <rhosts_file>`        remote hosts list file, newline delimited.  
- `-s <script_file>`        script file to be executed at remote host.  
- `-t <script_timeout>`     script execution timeout at remote host, default 60 seconds. 
- `-u <user-passwd_file>`   user credentials file.  

`e.g. -  $ java -jar Rexec.jar -r sample_hosts.lst -s sample_script.sh -u sample_user_credentials.lst`  

# Sample files
- sample_hosts.lst
```
hostA
```
- sample_script.sh
```shell
#/bin/ksh
ps -ef
exit
```
- sample_user_credentials.lst
```
user
password
## if script to be executed as sudo user e.g. sudo -k -u <user> provide the sudo user else no entry is required.
sudo user
```
