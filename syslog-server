######################################################################################################################
##################    THIS SCRIPT IS WRITTEN BY Mostafa Soliman ######################################################
##################    Email: Mostafa.Soliman.Zakria@hotmail.com ######################################################
##################    FEEL FREE TO COPY ,MODIFY OR USE IT       ######################################################
######################################################################################################################


#######################################################################################################################
#################                   WARRNING                     ######################################################
#################        THIS SCRIPT MAY CONTAIN SOME BUGS       ######################################################
################# REVIEW IT AND USE IT UNDER YOUR RESPONSIBILITY ######################################################
#######################################################################################################################

import socket
import re
import threading
import time
import sys
import xlrd
from netaddr import IPNetwork

ForbiddenNetworks=[]
def Read_Forbidden_Access(path):
    """
    Open and read an Excel file
    """
    global ForbiddenNetworks
    Dict={'srcNetwork':'','dstNetwork':'','dstPort':''}
    book = xlrd.open_workbook(path)
    first_sheet = book.sheet_by_index(0)
    for row in range(1,first_sheet.nrows):#escape first line
        if '/' not in str(first_sheet.row_values(row)[0]):
            Dict['srcNetwork']=IPNetwork(str(first_sheet.row_values(row)[0])+'/32')
        else:
            Dict['srcNetwork']=IPNetwork(str(first_sheet.row_values(row)[0]))
        if '/' not in str(first_sheet.row_values(row)[1]):
             Dict['dstNetwork']=IPNetwork(str(first_sheet.row_values(row)[1])+'/32')
        else:
            Dict['dstNetwork']=IPNetwork(str(first_sheet.row_values(row)[1]))
        Dict['protocol']=str(first_sheet.row_values(row)[2]).split('/')[0]    
        Dict['dstPort']=int(str(first_sheet.row_values(row)[2]).split('/')[1])
        ForbiddenNetworks.append(Dict)

            
            



class myThread (threading.Thread):
    def __init__(self, data):
        threading.Thread.__init__(self)
        self.data = data

    def run(self):
        # Get lock to synchronize threads
        threadLock.acquire()
        Check_Packet(self.data)
        # Free lock to release next thread
        threadLock.release()

RulesList=[] #container for the rules to be granted
def Check_Forbidden_Access(srcIP,dstIP,dstPort,protocol):
#check if dstIP&dstPort are in Forbidden area.
    for Net in ForbiddenNetworks:
        RdstIP=Net['dstNetwork']
        RsrcIP=Net['srcNetwork']
        RdstPort=Net['dstPort']
        Rprotocol=Net['protocol']
        if (IPNetwork(dstIP) in RdstIP ) and (RdstPort==int(dstPort)) and (IPNetwork(srcIP) in RsrcIP ) and (protocol==Rprotocol)  :

            print 'Forbidden access found',srcIP,'--->',dstIP,dstPort
            return True
    return False
            



def Name_to_IP(Name):
    fp=open('show run name.txt','r')
    output=fp.read()
    fp.close()

    for Line in output.split('\n'):
        if 'name' in Line:
            if Name==Line.split()[2]:

                return Line.split()[1]
    
    return 0
def Check_Packet(Line):
#read packet line and check if it is in Forbidden or not
    global RulesList
    Dict={}
    ACLName=Line.split()[6]
    protocol= Line.split()[8]
    srcInt=Line.split()[9].split('/')[0]
    srcIP=Line.split()[9].split('/')[1].split('(')[0]
    srcPort=Line.split()[9].split('/')[1].split('(')[1][:-1]
    
    dstInt=Line.split()[11].split('/')[0]
    dstIP=Line.split()[11].split('/')[1].split('(')[0]
    dstPort=Line.split()[11].split('/')[1].split('(')[1][:-1]

    if not re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',srcIP): # incase where names are used not ip
        srcIP=Name_to_IP(srcIP)

    if not re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',dstIP):
        dstIP=Name_to_IP(dstIP)



    if not Check_Forbidden_Access(srcIP,dstIP,dstPort,protocol):# incase legal access
        Dict['srcIP']=srcIP
        Dict['dstIP']=dstIP
        Dict['dstPort']=dstPort
        Dict['protocol']=protocol
        Dict['ACLName']=ACLName
        if Dict not in RulesList:
            RulesList.append(Dict)
        print srcIP,srcPort,'-->',dstIP,dstPort
        
        



def syslog_server():

    IP = "0.0.0.0"
    PORT = 514

    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
    sock.bind((IP, PORT))
    print 'server is listing'
    threadLock = threading.Lock()
    threads = []

    path = "forbidden.xlsx"
    Read_Forbidden_Access(path)
    print 'Forbidden access sheet read completed'
    while True:
        try:
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        except (KeyboardInterrupt, SystemExit):
            print 'Exiting server'
            for t in threads:
                t.join()
            print 'Writing Rules.'
            f=open('result.txt','w')
            for Dict in RulesList:
                f.write('access-list '+Dict['ACLName']+' line 1 permit '+Dict['protocol']+' host '+Dict['srcIP']+' host '+Dict['dstIP']+' eq '+Dict['dstPort']+'\n' )
            f.close()          
            print "Exiting Main Thread"
            sys.exit()

        if '106100' in data: #filter logs to 106100
            try:
                thread = myThread(data)
                thread.start()
                threads.append(thread)
            except (KeyboardInterrupt, SystemExit):
                print 'Exiting server'
                for t in threads:
                    t.join()
                print 'Writing Rules.'
                f=open('result.txt','w')
                for Dict in RulesList:
                    f.write('access-list '+Dict['ACLName']+' line 1 permit '+Dict['protocol']+' host '+Dict['srcIP']+' host '+Dict['dstIP']+' eq '+Dict['dstPort']+'\n' )
                f.close() 
                print "Exiting Main Thread"
                sys.exit()
                
if __name__ == '__main__':
    syslog_server()
