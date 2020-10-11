

import asyncio
import socket
import argparse
import json
import os
from urllib.parse import urljoin
from concurrent.futures import ProcessPoolExecutor
from urllib.parse import urlencode
import urllib.parse as urlparse
import logging
import datetime
import sys

import requests
import socketio
import scitokens
import jwt


loop = asyncio.get_event_loop()
sio = socketio.AsyncClient(reconnection_attempts=5)
start_timer = None

logging.basicConfig(level=logging.DEBUG)


def get_client_details():
    """
    :return dict: Details about the client
    """
    details = {}
    # Get the resource name
    details['hostname'] = socket.gethostname()

    # Get the GLIDEIN_ResourceName
    # Get the startd ad
    if os.path.exists('.startd.ad'):
        with open('.startd.ad') as startdad:
            # search for the GLIDEIN_ResourceName
            for line in startdad:
                if line.startswith("GLIDEIN_ResourceName"):
                    value = line.split("=", 1)[1]
                    # Check for quotes in value
                    if value.startswith('"'):
                        value = value[1:-1]
                    details['GLIDEIN_ResourceName'] = value
                    break
    
    # What other details do we want?

    return details

def register_client(server, token, is_server=False):
    """
    Register the client with the webserver

    :return str: client_id from server
    """
    # Gather information about the client
    details = get_client_details()
    final_url = urljoin(server, "register")
    if is_server:
        params = {
            'server': 1
        }
        url_parsed = urlparse.urlparse(final_url)
        url_parsed = url_parsed._replace(query = urlencode(params))
        #url_parsed = url_parsed._replace(scheme = "wss")
        final_url = urlparse.urlunparse(url_parsed)
        print(final_url)
    headers = {
        "Authorization": 'Bearer {}'.format(token)
    }
    resp = requests.post(final_url, json=details, headers=headers)

    try:
        resp_json = resp.json()
    except Exception as e:
        logging.error(resp.text)
        logging.exception("Error while trying to convert response to json:")
        return ""
    return resp_json['client_id']

def add_arguments():
    parser = argparse.ArgumentParser(description='Register and respond to commands from the server')
    parser.add_argument('server', type=str, help="The full https URL of the command server")
    parser.add_argument('--is-server', '-s', dest='is_server', action='store_true', 
                        help="If this client should act as a server, to be installed with a XRootD Server")
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('--token', '-t', type=str, dest='token', help="Location of a valid scitoken")
    auth_group.add_argument('--password', '-p', type=str, dest='password', help="Password to generate the authentication token")
    return parser

def xrootd_client(command):
    logging.debug("Running in new process")
    return "Returning from process"

@sio.event
async def command(message):
    """
    Parse the commands from the server
    """
    command = json.loads(message)
    loop = asyncio.get_event_loop()
    out = await loop.run_in_executor(ProcessPoolExecutor(max_workers=1),
                                          xrootd_client, command)
    logging.debug("Inside consumer function")
    logging.debug("Received command: {}".format(command))
    logging.debug("Received from the separate process: {}".format(out))
    return out


async def start_consumer(uri):
    await sio.connect(uri)
    await sio.wait()

def generate_token(password: str):
    """
    Generate a scitoken from the private key path.

    :arg password str: Password to generate token
    """
    token_details = {
        'scope': 'write:/register',
        'aud': 'https://xrootd-client-manager.opensciencegrid.org',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=20)
    }
    return jwt.encode(token_details, password, algorithm='HS256').decode('utf-8')
    

def main():
    # Get the arguments
    parser = add_arguments()
    args = parser.parse_args()

    # Get the token, whether it has to be generated or if it can be read
    token = ""
    if args.token:
        with open(args.token, 'r') as token_file:
            token = token_file.read()
    else:
        token = generate_token(args.password)
        
    logging.debug("Using token: {}".format(token))
    # Register client
    client_id = register_client(args.server, token, args.is_server)
    if not client_id:
        logger.error("Unable to get client token from server, exiting")
        sys.exit(1)

    # Now listen to the websocket for test commands
    #websocket_uri = urljoin(args.server, "listen")
    websocket_uri = args.server
    params = {
        'id': client_id
    }
    if args.is_server:
        params['server'] = 1
    url_parsed = urlparse.urlparse(websocket_uri)
    url_parsed = url_parsed._replace(query = urlencode(params))
    #url_parsed = url_parsed._replace(scheme = "wss")
    websocket_uri = urlparse.urlunparse(url_parsed)
    print(websocket_uri)
    
    #websocket = websockets.connect(websocket_uri)
    asyncio.get_event_loop().run_until_complete(start_consumer(websocket_uri))

if __name__ == "__main__":
    main()
