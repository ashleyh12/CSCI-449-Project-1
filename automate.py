import subprocess

def traceroute(hostname):
    '''
    This will take in our hostname or IP address and return a list of the IP hops
    '''
    traceroute = subprocess.Popen(["traceroute",hostname],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ipList = []
    for line in iter(traceroute.stdout.readline,b""):
        line = line.decode("UTF-8")
        IP = line.split("  ")
        if len(IP)>1:
            IP = IP[1].split("(")
            if len(IP)>1:
                IP = IP[1].split(")")
                ipList.append(IP[0])
    return ipList
