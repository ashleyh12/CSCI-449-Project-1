import socket
import sys
import subprocess
import ipaddress
import json
import requests
import plotly.graph_objects as go


def traceroute(hostname):
    '''
    This will take in our hostname or IP address and return a list of the IP hops
    '''
    traceroute = subprocess.Popen(["traceroute",hostname],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ipList = []
    for line in iter(traceroute.stdout.readline,b""):
        line = line.decode("UTF-8")
        IP = line.split("  ")
        if len(IP) > 1:
            IP = IP[1].split("(")
            if len(IP) > 1:
                IP = IP[1].split(")")
                ipList.append(IP[0])
    return ipList


def getLocation():
    '''
    This part of the code returns MyIP, longitude, latitude, and the city
    '''
    url = 'https://ipapi.co/json/'
    response = requests.get(url)
    data = response.json()
    try:
        myIP = data['ip']
        lon = data['longitude']
        lat = data['latitude']
        city = data['city']
    except KeyError as a:
        print('Error not found')
        exit()
    return (myIP, (lon,lat), city)


def getFinalIP(IP):
    '''
    This part of the code takes in IP address and returns its' longitude, latitude, and the city
    '''
    url = f'https://ipapi.co/{IP}/json/'
    response = request.get(url)
    data = response.json()
    try:
        lon = data['longitude']
        lat = data['latitude']
        city = data['city']

    
