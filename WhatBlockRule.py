import datetime
import digitalocean
import iptools
import json
import os
import Queue
import shlex
import string
import subprocess
import sys
import threading
import time
import unirest
import paramiko
from netaddr import *

paramiko.util.log_to_file("paramiko.log")
startingPath = os.getcwd()
outputEnabled = True
verboseOutput = True
MAX_THREADS = 25
default_ssh_user = "root"
default_ssh_key = "XXX"
default_ssh_port = 22
do_token = "XXX"
key_fingerprint = "XXX"


def printMsg(messageText, messageType, isLogged, solutionName, logDirectory):
    if isLogged is True:
        if not os.path.exists(logDirectory):
            os.makedirs(logDirectory)
        f = open(
            logDirectory
            + "/"
            + solutionName
            + "-"
            + "{:%m-%d-%Y}".format(datetime.date.today())
            + ".log",
            "a",
        )
        f.write(
            "{:%m-%d-%Y %H:%M:%S}".format(datetime.datetime.now())
            + ": "
            + messageText
            + "\n"
        )
        f.close()
    if outputEnabled is True:
        if messageType == 0:
            print("[+] " + messageText)
        if verboseOutput is True and messageType == 1:
            print("[!] " + messageText)


class DigitalOcean:
    def __init__(self):
        self.dropletCount = 0
        self.token = do_token
        self.k = default_ssh_key
        self.sshFingerprint = key_fingerprint

    def newDroplet(self, dropletName=""):
        global dropletCount
        while len(dropletName) < 1:
            dropletName = raw_input("Please enter the name of the new droplet: ")
        apiReq = (
            "curl -s -X POST -H 'Content-Type: application/json' "
            + "-H 'Authorization: Bearer "
            + self.token
            + '\' -d \'{"name":"'
            + dropletName
            + '",'
            + '"region":"sfo2","size":"512mb","image":"debian-9-x64",'
            + '"ssh_keys": [ "'
            + self.sshFingerprint
            + "\" ] }' "
            + '"https://api.digitalocean.com/v2/droplets"'
        )
        try:
            proc = subprocess.check_output(shlex.split(apiReq))
        except Exception as e:
            sendOutput(str(e))
            sys.exit()
        time.sleep(5)
        x = True
        while x:
            try:
                dropletInfo = json.loads(proc)
                dropletID = dropletInfo["droplet"]["id"]
                x = False
            except Exception as e:
                pass
        self.getAllDroplets()
        for droplet in self.allDroplets:
            if dropletID == droplet.id:
                droplet = self.waitUntilDropletActive(droplet)
                self.currentDroplet = droplet
                self.newDroplet = self.currentDroplet

    def waitUntilDropletActive(self, droplet):
        kill = False
        while kill is False:
            time.sleep(10)
            try:
                self.getSingleDroplet(droplet.id)
                if self.currentDroplet.status == "active":
                    kill = True
                    return droplet
            except Exception as e:
                sendOutput(str(e))
                pass

    def getSingleDroplet(self, dropletID):
        manager = digitalocean.Manager(token=self.token)
        self.currentDroplet = manager.get_droplet(dropletID)

    def getAllDroplets(self):
        manager = digitalocean.Manager(token=self.token)
        self.allDroplets = manager.get_all_droplets()

    def deleteDroplet(self, droplet):
        try:
            droplet.destroy()
        except Exception as e:
            sendOutput(str(e))
            pass


class Session:
    def __init__(self):
        self.hostname = ""
        self.sshPort = default_ssh_port
        self.sshUser = default_ssh_user
        self.sshKey = default_ssh_key

    def connect(self):
        if self.hostname:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.hostname,
                username=self.sshUser,
                key_filename=self.sshKey,
                port=self.sshPort,
            )
            self.session = ssh
        if not self.hostname:
            print(
                "No remote SSH host is defined. Please set the hostname property to the target host in order to connect"
            )

    def execute(self, command):
        ssh_stdin, ssh_stdout, ssh_stderr = self.session.exec_command(command)
        self.lastCommandOutput = "".join(ssh_stdout.readlines())
        return self.lastCommandOutput

    def closeSession(self):
        self.session.close()


def sendOutput(msg, messageType=0):
    isLogged = True
    solutionName = "MariNeMAP"
    logDirectory = "Logs"
    printMsg(msg, messageType, isLogged, solutionName, logDirectory)


def cleanupWorkers():
    fndo = DigitalOcean()
    fndo.getAllDroplets()
    for droplet in fndo.allDroplets:
        if "scanning-" in droplet.name:
            droplet.destroy()


def PaloAltoNmapper(addr):
    doAPI = DigitalOcean()
    sess = Session()
    if str(addr).split(".")[3] != "0":
        # try:
        addr = str(addr)
        sendOutput("New scan job started against address " + addr)
        doAPI.newDroplet("scanning-" + addr.replace(".", "-"))
        someVar = True
        while someVar:
            try:
                if doAPI.newDroplet.ip_address:
                    sess.hostname = doAPI.newDroplet.ip_address
                    sess.connect()
                    someVar = False
            except:
                pass
        sendOutput("Connected to new droplet at " + sess.hostname, 1)
        sess.execute("apt-get update && apt-get install nmap -y")
        nmapOutput = sess.execute("nmap -sS --open -Pn -vv -n -F -oG - " + addr)
        sendOutput("Writing nmap results from " + addr)
        f = open("nmap-stealth-" + addr.replace(".", "-") + ".gnmap", "w")
        f.write(nmapOutput)
        f.close()
        sess.closeSession()
        doAPI.deleteDroplet(doAPI.newDroplet)
        sendOutput("Droplet destroyed (" + sess.hostname + ")", 1)


class ThreadScans(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            host = self.queue.get()
            PaloAltoNmapper(host)
            self.queue.task_done()


def main():
    queue = Queue.Queue()
    hosts = iptools.IpRangeList(netRange)
    # In case it's not obvious, this could be a list of whatever
    for host in hosts:
        queue.put(host)
    delayTime = 4
    for thr in range(MAX_THREADS):
        time.sleep(delayTime)
        delayTime = delayTime
        t = ThreadScans(queue)
        t.setDaemon(True)
        t.start()
    queue.join()


try:
    netRange = sys.argv[1]
except:
    sys.exit("Please supply a network range (e.g. 192.168.1.0/24)")

main()
cleanupWorkers()
