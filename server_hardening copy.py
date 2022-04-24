#!/usr/bin/python

from datetime import datetime
import os
import shutil
import platform

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
            if '#' in line and self.s_string in line:
                self.s_string = '#' + self.s_string
                line = line.replace(self.s_string,self.r_string)
                replace_file = replace_file + line
            else:
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
        file.write(self.lines_2add)
        self.result.write_output(f"\tLine'{self.lines_2add}' has added to '{self.source}'")

    def restartservice(self,service):
        self.service = service
        os.system('systemctl daemon-reload')
        validation = os.system(f'systemctl restart {self.service}')
        if validation == 0:
            self.result.write_output( f'{self.service} has been restarted successfully')
        else: 
            self.result.write_output(f'{self.service} is not started successfully, please check errors manually')
        
def filetovar(filename):
    file = open(filename,'r')
    filevar = ''
    for line in file:
       filevar = filevar + line
    return filevar        

os_name = OS_details()
result_file_name = f'hardening_result_{today.strftime("%d_%m_%Y_%H_%M_%S")}.txt'
result_file = Output(result_file_name)
result_file.create_file()


#SSH Hardening Steps
if os_name.oscheck() == 'Linux':
    result_file.write_output('SSH Hardening outputs:-')
    ssh_harden = Harden(result_file_name,'/etc/ssh/sshd_config')
    ssh_harden.backup()
    ssh_harden.linereplace('PermitRootLogin yes','PermitRootLogin no')
    ssh_file = filetovar(ssh_harden.source)
    if "AllowUsers" not in ssh_file:
        print(f'AllowUsers not found in {ssh_harden.source}')
        yes_no = input('Do you want to add AllowUsers(yes/no): ').lower()
        if yes_no == 'yes':
            usernames = input('Please provide the usernames seperated by comma: ')
            ssh_harden.addlines(f'AllowUsers {usernames}')
    elif "AllowUsers" in ssh_file:
        print(f'AllowUsers found in {ssh_harden.source}')
        yes_no = input('Do you want to add AllowUsers(yes/no): ').lower()
        if yes_no == 'yes':
            usernames = input('Please provide the usernames seperated by comma: ')
            for line in ssh_file:
                if "AllowUsers" in line:
                    newline = line + usernames
                    ssh_harden.linereplace(line,newline)
    ssh_harden.restartservice('sshd')
else: 
    result_file.write_output(f'Operating system is {os_name.oscheck()}, So skipping SSH hardening')
    






