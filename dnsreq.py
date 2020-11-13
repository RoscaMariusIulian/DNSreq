import socket
import sys
from random import randint
import datetime
from subprocess import DEVNULL, STDOUT, check_call

def sendRequest():
    #1.Se construieste mesajul DNS
    value= randint(0,10)
    domeniu = "riweb.tibeica.com"
    check_call(['nslookup ', domeniu], stdout=DEVNULL, stderr=STDOUT)
    msj = bytearray(12+len(domeniu)+6)
    msj[1]=0xFF&value+1
    msj[5]=0x01
    sendID = (((0xFF) & msj[0]) << 8) | (0xFF & msj[1])
    #print(socket.gethostbyname(domeniu))  functie pt a obtine ip-ul din domeniu
    labels = domeniu.split(".")
    idx = 12
    for i in labels:
        tmp = len(i)
        msj[idx]=tmp&0xFF
        idx=idx+1
        for j in i:
            msj[idx]=ord(j)
            idx=idx+1
    msj[idx]=0
    msj[idx+2]=0x1
    msj[idx+4]=0x1
    #print(msj)
    #2.Se transmite mesajul
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address= ("192.168.1.254",53) #how to get this addr 192.168.1.254 ns1.digitalocean.com
    sent= sock.sendto(msj,server_address)
    
    #3.Se preia raspunsul
    response = bytearray(512)
    response, server = sock.recvfrom(512)
    sock.close()
    
    #4.Se prelucreaza raspunsul
    recivID=(((0xFF) & response[0]) << 8) | (0xFF & response[1])
    if recivID == sendID:
        print("ID-urile se potrivesc, se parseaza raspunsul mai departe..")
    if (response[3] & 0x0F) == 0x00:
        print("RCode 0 -> OK, se parseaza raspunsul mai departe..")
    else:
        errorCode = response[3] & 0x0F;
        print("Eroare: RCode = " + str(errorCode))
        
    noResp = (((0xFF) & response[6]) << 8) | (0xFF & response[7])
    print("Numarul de raspunsuri primite: " + str(noResp)) 

    noAuth = (((0xFF) & response[8]) << 8) | (0xFF & response[9])
    print("Numarul de informatii despre autoritati primite: " + str(noAuth))
    
    noRec = (((0xFF) & response[10]) << 8) | (0xFF & response[11])
    print("Numarul de informatii aditionale primite: " + str(noRec))
    
    index = 12 + len(domeniu) + 6;
    
    if noRec +  noAuth + noResp == 0:
        print("Nicio informatie primita de la server.")  
        
    print("Informatiile primite de la server sunt:")
    #Domeniu
    respDomain = getDNS(response, index)[:-1] #to do
    if (response[index] & 0xFF) < 192:
        index = index + len(respDomain) + 1 #change
    else:
        index = index + 1
    print("Domeniu: " + respDomain)
    #Record Type
    index = index + 1
    MSB = response[index]
    index = index + 1
    LSB = response[index]
    recordType = (((0xFF) & MSB) << 8) | (0xFF & LSB)
    print(" | Record Type: " + str(recordType))
    if (recordType == 1): 
        print(" (adresa IPv4)")
    elif (recordType == 2): 
        print(" (server de nume)")
    elif (recordType == 5): 
        print(" (nume canonic)")
    elif (recordType == 28): 
        print(" (adresa IPv6)")
    #Record Class  
    index = index+1
    MSB = response[index]
    index = index+1
    LSB = response[index]
    recordClass = (((0xFF) & MSB) << 8) | (0xFF & LSB)
    print(" | Record Class: " + str(recordClass))
    if (recordClass == 1):
        print(" (internet)")
    #TTL    
    index = index+1    
    b3 = response[index]
    index = index+1
    b2 = response[index]
    index = index+1
    b1 = response[index]
    index = index+1
    b0 = response[index]
    TTL = ((0xFF & b3) << 24) | ((0xFF & b2) << 16) | ((0xFF & b1) << 8) | (0xFF & b0)
    d = datetime.timedelta(seconds=TTL)
    print(" | TTL: " + str(d))
    #IP
    index = index+1
    MSB = response[index]
    index = index+1
    LSB = response[index]
    dataLen = (((0xFF) & MSB) << 8) | (0xFF & LSB)
    word = ""
    if dataLen == 4 and recordType == 1:
        for i in range(dataLen):
            index = index+1
            word =word + str(response[index]& 0xFF) + "."
        word=word[:-1]
        print(" | Adresa IPv4: "+str(word))
    elif dataLen == 16 and recordType == 28:
        for i in range(dataLen):
            index = index+1
            word =word + str(response[index]& 0xFF) + "."
        word=word[:-1]
        print(" | Adresa IPv6: "+str(word))
    elif recordType == 2:
        nsName = getDNS(index, response)
        index = index + len(nsName)
        print(" | Server de nume: " + str(nsName))
    elif (recordType == 5):
        canonicalName = getDNS(index, response)
        index = index + len(anonicalName)
        print(" | Nume canonic: " + str(canonicalName))
          
def getDNS(resp, idx):
    if (resp[idx]& 0xFF) == 0x0:
        return ""
    if (resp[idx] & 0xFF) >= 192:
        newIdx=((resp[idx] & 0x3F) << 8) | (resp[idx+1] & 0xFF)
        return getDNS(resp, newIdx)
    i=(resp[idx] & 0xFF)+1
    word =""
    for j in range(1, i):
        word =word + chr(resp[idx+j])
    idx = idx + i
    return word + "." + getDNS(resp, idx)
        
def main():
    sendRequest()
       
if __name__=="__main__":
    main()