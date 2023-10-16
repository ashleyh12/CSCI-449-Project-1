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


def getMyLocation():
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
    except KeyError as a:
        print('Error not found')
        exit()
    return (IP, (lon,lat), city)


def getListLoc(ipList):
    '''
    Get's Ip address list and returns a list of tuples of IP, longitude, latitude, and the city
    '''
    List = []
    for ipAddress in ipList:
        url = f'https://ipapi.co/{ipAddress}/json/'
        response = requests.get(url)
        data = response.json()
        
        # This is to check if the IP address is private or not
        try:
            if data['error'] == True:
                continue
        except KeyError:
            pass

        lon = data['longitude']
        lat = data['latitude']
        if lon == None or lat == None:
            continue
        city = data['city']
        List.append((ipAddress,(lon,lat),city))

    return List

def mapInitization(fig):

    fig.update_layout(
    margin = {'l':50,'t':50,'b':50,'r':50},
    mapbox = {
        'center': {'lon': 10, 'lat': 10},
        'style': "stamen-terrain",
        'center': {'lon': -20, 'lat': -20},
        'zoom': 1})

def addingRoute(fig,name,position):
    '''
    setting up the name and position (longitude and latitude) of the route)
    '''
    lonRoute = position[0][0]
    latRoute = position[0][1]
    city = position[1]
    fig.add_trace(go.Scattermapbox
        (
        name = name,
        text = city,
        mode = "markers+lines",
        lon = lonRoute,
        lat = latRoute,
        marker = {'size':10})
        )

def mark(fig ,markName, position,name='My IP'):
    '''
    Marks the IP address on the map
    '''
    lonPath = position[0]
    latPath = position[1]
    fig.add_trace(go.Scattermapbox(
        name = name,
        text = markName,    
        mode = "markers+text",
        lon = (lonPath,),
        lat = (latPath,),
        marker = {'size': 15}
        ))
    
def printHelp():
    print('''Use the code by typing in the following format:
        python3 traceroute.py [hostname]
    Example:
        python3 traceroute.py Howard.edu
    ''')
    
if len(sys.argv)<2:
    printHelp()
    exit()
    
hostname = sys.argv[1]

# get my location (myIP,(lon,lat),city)
myLoc = getMyLocation()

# get the IP address of the target. Run trace route then find the long and lat
targetIP = socket.gethostbyname(hostname)
targetLoc = getFinalIP(targetIP)
ipList = traceroute(hostname)
routeLocList = getMyLocation(ipList)
routeLocList.insert(0,myLoc)
routeLocList.append(targetLoc)
routeLocLon = []
routeLocLat = []
tempLon = 0
tempLat = 0
# This is to add the route to the map
for x in routeLocList:
    if x[1][0]-tempLon == 0 or x[1][1]-tempLat == 0:
        continue
    routeLocLon.append(x[1][0])
    routeLocLat.append(x[1][1])
    tempLon = x[1][0]
    tempLat = x[1][1]


# creating the map(s)
fig = go.Figure()
mapsInit(fig)
