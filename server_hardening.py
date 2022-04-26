#!/usr/bin/python

from datetime import datetime
import os
import shutil
import platform
import subprocess as sp

today = datetime.now()

class Output():
    def __init__(self,outputfile):
        self.outputfile = outputfile

    def create_file(self):
        output_file = open(self.outputfile,'w')
        output_file.write(">> This file is created to write the result of server hardening <<\n")
        output_file.close()
    
    def write_output(self,result):
        self.result = result
        output_file = open(self.outputfile,'a')
        output_file.write(f'\n {result} \n')
        output_file.close()

class OS_details():
    
    def __init__(self) -> None:
        pass

    def oscheck(self):
        osname = platform.system()
        if 'linux' in osname.lower():
            return 'Linux'
        elif 'windows' in osname.lower():
            return 'Windows'

    def flavour_check(self):
        flavour_name = platform.platform()
        if 'red hat' in flavour_name.lower():
            return 'Redhat' 
        elif 'centos' in flavour_name.lower():
            return 'CentOS'
        elif 'ubuntu' in flavour_name.lower():
            return 'Ubuntu'
        elif 'debian' in flavour_name.lower():
            return 'Debian'
        else:
            return 'OS not detected'

class Harden():

    def __init__(self,resultfile,source):
        self.source = source
        self.destination = source + '_' + today.strftime("%d_%m_%Y_%H_%M_%S")
        self.resultfile = resultfile
        self.result = Output(self.resultfile)
        
    def backup(self):
        shutil.copy(self.source,self.destination)
        self.result.write_output(f"\t'{self.source}' has been backed to '{self.destination}'")

    def linereplace(self,s_string,r_string):
        self.s_string = s_string
        self.r_string = r_string
        replace_file = ""
        file = open(self.source, 'r')
        for line in file:
            line = line.replace(self.s_string,self.r_string)
            replace_file = replace_file + line
        file.close()

        file = open(self.source, 'w')
        file.write(replace_file)
        file.close()
        self.result.write_output(f"\t'{self.s_string}' has been replaced with '{self.r_string}'")
    
    def addlines(self,lines_2add):
        self.lines_2add = lines_2add
        file = open(self.source, 'a')
        file.write(f'{self.lines_2add}\n')
        self.result.write_output(f"\tLine'{self.lines_2add}' has added to '{self.source}'")

    def restartservice(self,service):
        self.service = service
        os.system('systemctl daemon-reload')
        validation = os.system(f'systemctl restart {self.service}')
        if validation == 0:
            self.result.write_output( f'\t{self.service} has been restarted successfully')
        else: 
            self.result.write_output(f'\t{self.service} is not started successfully, please check errors manually')
        
    def find_start_string(self,check_string):
        self.check_string = check_string
        file = open(self.source,'r')
        lines = file.readlines()
        file.close()
        result = ''
        for line in lines:
            if line.startswith(check_string):
                result = result + line
        return result.strip()

def yes_or_no(string):
    yes_no = input(f'Do you want to add {string}(yes/no): ').lower()
    if 'yes' in yes_no or 'y' in yes_no:
        return True
    else:
        return False

def yes_no_continue():
    yes_no = input(f'Do you want to continue (yes/no): ').lower()
    if 'yes' in yes_no or 'y' in yes_no:
        return True
    else:
        return False

def starting(comment):
    print(f'{comment} is started now and it will take sometime...')
def completed(comment):
    print(f'{comment} is Completed now....')

def linux_command(*packages):
    for item in packages:
        result_file.write_output(f"{sp.getoutput(item)}")


os_name = OS_details()
result_file_name = f'/tmp/hardening_result_{today.strftime("%d_%m_%Y_%H_%M_%S")}.txt'
result_file = Output(result_file_name)
result_file.create_file()

# Updating all the packages
if os_name.oscheck() == 'Linux11':
    result_file.write_output('\n 1. Updating packages output:-') 
    starting('Package updation')
    if os_name.flavour_check() == 'Redhat' or os_name.flavour_check() == 'CentOS':
        linux_command('yum clean all','yum update -y')
    elif os_name.flavour_check == 'Ubuntu' or os_name.flavour_check() == 'Debian':
        linux_command('apt-get update','apt-get upgrade')
    else: 
        result_file.write_output(f'\t OS not dected so skipping the step updating packages')
    completed('Package updation')
else:
    result_file.write_output(f'Operating system is {os_name.oscheck()}, So skipping package updation')

#SSH Hardening Steps
if os_name.oscheck() == 'Linux11':
    result_file.write_output('2. SSH Hardening outputs:-')
    starting('SSH hardening')
    ssh_harden = Harden(result_file_name,'/etc/ssh/sshd_config')
    # Taking backup of the ssh configuration file
    ssh_harden.backup()
    # this will help to replace even if we have multiple "PermitRootLogin yes" or "PermitRootLogin no" lines in sshd_config 
    permitroot = ssh_harden.find_start_string('PermitRootLogin')
    if permitroot: 
        ssh_harden.linereplace('PermitRootLogin yes','PermitRootLogin no')
    else:
        ssh_harden.addlines('PermitRootLogin no')
    # This is to add AllowUsers or modify the AllowUsers    
    ssh_allowusers = ssh_harden.find_start_string('AllowUsers')
    if ssh_allowusers:       
        print(f'AllowUsers active in {ssh_harden.source} and currently line is like below \n {ssh_allowusers}')
        if yes_or_no('AllowUsers'):
            usernames = input('Please provide the usernames seperated by space(example: john adams jose): ')
            newline = ssh_allowusers + ' ' + usernames
            ssh_harden.linereplace(ssh_allowusers,newline)
    else:
        print(f'AllowUsers not active {ssh_harden.source}')
        if yes_or_no('AllowUsers'):
            usernames = input('Please provide the usernames seperated by space(example: john adams jose): ')
            ssh_harden.addlines(f'AllowUsers {usernames}')
    # This is to add Ciphers to ssh confiuration files
    ssh_ciphers = ssh_harden.find_start_string('Ciphers')
    if ssh_ciphers:
        print(f'Ciphers active in {ssh_harden.source} and currently line is like below \n {ssh_ciphers}')
        if yes_or_no('Ciphers'):
            ciphers = input('Please provide the ciphers seperated by comma(example: aes128-ctr, aes192-ctr): ')
            newline = ssh_ciphers + ',' + ciphers
            ssh_harden.addlines(ssh_ciphers,newline)
    else:
        print(f'Ciphers not active {ssh_harden.source}')
        if yes_or_no('Ciphers'):
            def_ciphers = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
            ciphers = input(f'Please provide the ciphers seperated by comma(example: aes128-ctr, aes192-ctr) \n default is {def_ciphers}:') or def_ciphers
            ssh_harden.addlines(f'Ciphers {ciphers}') 
    # Restarting SSHD service 
    ssh_harden.restartservice('sshd')
    completed('SSH Hardening')
else: 
    result_file.write_output(f'Operating system is {os_name.oscheck()}, So skipping SSH hardening')

#Sysctl.conf Hardening steps
if os_name.oscheck() == 'Linux11':
    result_file.write_output('3. Sysctl conf Hardening outputs:-')
    starting('Sysctl_conf hardening')
    sysctl_harden = Harden(result_file_name,'/etc/sysctl.conf')
    #Taking backup of the sysctl configuration file
    sysctl_harden.backup()
    #Adding the required lines to sysctl.conf
    sys_lines = ['net.ipv4.conf.all.accept_redirects','net.ipv4.conf.default.accept_redirects','net.ipv4.conf.all.secure_redirects','net.ipv4.conf.default.secure_redirects', 'net.ipv4.tcp_timestamps']
    for line in sys_lines:
        if not sysctl_harden.find_start_string(line):
            sysctl_harden.addlines(f'{line} = 0')
        elif '0' not in sysctl_harden.find_start_string(line):
            sysctl_harden.linereplace(line,f'#{line}')
            sysctl_harden.addlines(f'{line} = 0')
        else:    
            result_file.write_output(f"\t'{line} = 0' is already in {sysctl_harden.source}")
    #Applying the changes to sysctl.conf
    os.system('sysctl -p')
    completed('Sysctl_conf hardening')
else:
    result_file.write_output(f'Operating system is {os_name.oscheck()}, So skipping Sysctl conf hardening')

#Setting Password Policy and Expiry
if os_name.oscheck() == 'Linux11':
    result_file.write_output('4. Setting Password policy and Expiry policy:-')
    starting('Setting Password Policy and Expiry')
    password_harden = Harden(result_file_name,'/etc/login.defs')
    #Taking backup of the login.defs configuration file
    password_harden.backup()
    #Modifing the password policies and expiry policies
    password_lines = {'PASS_MAX_DAYS':'90','PASS_MIN_DAYS':'7','PASS_MIN_LEN':'12','PASS_WARN_AGE':'7'}
    for key in password_lines.keys():
        if not password_harden.find_start_string(key):
            password_harden.addlines(f'{key} {password_lines[key]}')
        else:
            password_harden.linereplace(key,f'#{key}')
            password_harden.addlines(f'{key} {password_lines[key]}')
    completed('Setting Password Policy and Expiry')
else:
    result_file.write_output(f'Operating system is {os_name.oscheck()}, So skipping the steps for setting Password Policy and Expiry')

# Chronyd installation and setting up timeservers
if os_name.oscheck() == 'Linux':
    result_file.write_output('5. Setting up chronyd for time:-')
    starting('Setting Up chronyd for time task')
    chronyd_harden = Harden(result_file_name,'/etc/chrony.conf')
    chrony_status = sp.run(['systemctl','status','chronyd'])
    lines = ['server 192.168.1.1 prefer iburst minpoll 4 maxpoll 4', 'server 192.168.1.2 prefer iburst minpoll 4 maxpoll 4']
    if chrony_status.returncode == '0' or chrony_status.returncode == '3':
        chronyd_harden.backup()
        for line in lines:
            if not chronyd_harden.find_start_string(line):
                chronyd_harden.addlines(line)
            else:
                result_file.write_output(f'Chronyd already installed and correct conf also present')
    else:
        linux_command('yum install chrony -y')
        for line in lines:
            chronyd_harden.addlines(line)
    chronyd_harden.restartservice('chronyd')  
    completed('Setting Up chronyd for time task')   
        



    







    


   



