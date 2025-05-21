#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
EMC Unity Storage monitoring script for Zabbix.
Collects health status and other metrics from EMC Unity storage systems via REST API
and sends them to Zabbix server.
"""

import os
import time
import argparse
import sys
import json
import subprocess
import logging
import logging.handlers
import requests
import urllib3
#urllib3.disable_warnings()
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def api_connect(api_user: str, api_password: str, api_ip: str, api_port: str) -> requests.Session:
  """
  Connect to Unity REST API and authenticate.
  
  Args:
    api_user: Username for Unity REST API
    api_password: Password for Unity REST API
    api_ip: IP address of Unity storage system
    api_port: Port number for Unity REST API
    
  Returns:
    authenticated requests Session object
    
  Raises:
    SystemExit: If connection or authentication fails
  """
  api_login_url = "https://{0}:{1}/api/types/loginSessionInfo".format(api_ip, api_port)
  session_unity = requests.Session()
  session_unity.auth = (api_user, api_password)
  session_unity.headers = {'X-EMC-REST-CLIENT': 'true', 'Content-type': 'application/json', 'Accept': 'application/json'}

  try:
    login = session_unity.get(api_login_url, verify=False)
  except Exception as oops:
    unity_logger.error("Connection Error Occurs: {0}".format(oops))
    sys.exit("50")

  if login.status_code != 200:
    unity_logger.error("Connection Return Code = {0}".format(login.status_code))
    sys.exit("60")
  elif login.text.find("isPasswordChangeRequired") >= 0: # If i can find string "isPasswordChangeRequired" therefore login is successful
    unity_logger.info("Connection established")
    return session_unity
  else:
    unity_logger.error("Login Something went wrong")
    sys.exit("70")



def api_logout(api_ip: str, session_unity: requests.Session) -> None:
  """
  Logout from Unity REST API session.
  
  Args:
    api_ip: IP address of Unity storage system
    session_unity: Authenticated session object
    
  Raises:
    SystemExit: If logout fails
  """
  api_logout_url = "https://{0}/api/types/loginSessionInfo/action/logout".format(api_ip)
  session_unity.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

  try:
    logout = session_unity.post(api_logout_url, verify=False)
  except Exception as oops:
    unity_logger.error("Logout Error Occurs: {0}".format(oops))
    sys.exit("150")

  if logout.status_code != 200:
    unity_logger.error("Logout status = {0}".format(logout.status_code))
    sys.exit("160")
  elif logout.text.find("Logout successful") >= 0:
    unity_logger.info("Logout successful")
  else:
    unity_logger.error("Logout Something went wrong")
    sys.exit("170")


def convert_to_zabbix_json(data: list) -> str:
  """
  Convert data to Zabbix JSON format.
  
  Args:
    data: List of items to convert to Zabbix JSON format
    
  Returns:
    JSON string in Zabbix format
  """
  output = json.dumps({"data": data}, indent = None, separators = (',',': '))
  return output



def send_data_to_zabbix(zabbix_data: list, storage_name: str) -> int:
  """
  Send collected data to Zabbix server.
  
  Args:
    zabbix_data: List of formatted data items to send
    storage_name: Name of the storage system
    
  Returns:
    Return code from zabbix_sender
  """
  sender_command = "/usr/bin/zabbix_sender"
  config_path = "/etc/zabbix/zabbix_agentd.conf"
  time_of_create_file = int(time.time())
  temp_file = "/tmp/{0}_{1}.tmp".format(storage_name, time_of_create_file)

  with open(temp_file, "w") as f:
    f.write("")
    f.write("\n".join(zabbix_data))

  send_code = subprocess.call([sender_command, "-vv", "-c", config_path, "-s", storage_name, "-T", "-i", temp_file], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
  os.remove(temp_file)
  return send_code



def discovering_resources(api_user: str, api_password: str, api_ip: str, api_port: str, storage_name: str, list_resources: list) -> int:
  """
  Discover resources from Unity storage system.
  
  Args:
    api_user: Username for Unity REST API
    api_password: Password for Unity REST API
    api_ip: IP address of Unity storage system
    api_port: Port number for Unity REST API
    storage_name: Name of the storage system
    list_resources: List of resource types to discover
    
  Returns:
    Return code from sending data to Zabbix
    
  Raises:
    SystemExit: If resource discovery fails
  """
  api_session = api_connect(api_user, api_password, api_ip, api_port)

  xer = []
  try:
    for resource in list_resources:
      resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name".format(api_ip, api_port, resource)
      resource_info = api_session.get(resource_url, verify=False)
      resource_info = json.loads(resource_info.content.decode('utf8'))

      discovered_resource = []
      for one_object in resource_info['entries']:
        if ['lun', 'pool'].count(resource) == 1:
          one_object_list = {}
          one_object_list["{#ID}"] = one_object['content']['id']
          one_object_list["{#NAME}"] = one_object['content']['name'].replace(' ', '_')
          discovered_resource.append(one_object_list)
        else:
          one_object_list = {}
          one_object_list["{#ID}"] = one_object['content']['id']
          discovered_resource.append(one_object_list)
      converted_resource = convert_to_zabbix_json(discovered_resource)
      timestampnow = int(time.time())
      xer.append("%s %s %s %s" % (storage_name, resource, timestampnow, converted_resource))
  except Exception as oops:
    unity_logger.error("Error occurs in discovering")
    sys.exit("1000")

  api_session_logout = api_logout(api_ip, api_session)
  return send_data_to_zabbix(xer, storage_name)



def get_status_resources(api_user: str, api_password: str, api_ip: str, api_port: str, storage_name: str, list_resources: list) -> int:
  """
  Get status of resources from Unity storage system.
  
  Args:
    api_user: Username for Unity REST API
    api_password: Password for Unity REST API
    api_ip: IP address of Unity storage system
    api_port: Port number for Unity REST API
    storage_name: Name of the storage system
    list_resources: List of resource types to check
    
  Returns:
    Return code from sending data to Zabbix
    
  Raises:
    SystemExit: If resource status collection fails
  """
  api_session = api_connect(api_user, api_password, api_ip, api_port)

  state_resources = [] # This list will persist state of resources (pool, lun, fcPort, battery, diks, ...) on zabbix format
  try:
    for resource in list_resources:
      # Create different URI for different resources
      if ['pool'].count(resource) == 1:
        resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeUsed,sizeSubscribed".format(api_ip, api_port, resource)
      elif ['lun'].count(resource) == 1:
        resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeAllocated".format(api_ip, api_port, resource)
      else:
        resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,needsReplacement".format(api_ip, api_port, resource)

      # Get info about one resource
      resource_info = api_session.get(resource_url, verify=False)
      resource_info = json.loads(resource_info.content.decode('utf8'))
      timestampnow = int(time.time())

      if ['ethernetPort', 'fcPort', 'sasPort'].count(resource) == 1:
        for one_object in resource_info['entries']:
          key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
          key_status = "link.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
          state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))

          # Get state of interfaces from description
          descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Convert description to string
          if descriptionIds.find("LINK_UP") >= 0: # From description i can known, link is up or link is down
            link_status = 10
          elif descriptionIds.find("LINK_DOWN") >=0:
            link_status = 11

          state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, link_status))

      elif ['lun'].count(resource) == 1:
        for one_object in resource_info['entries']:
          key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Use lun name instead lun id on zabbix key
          key_sizeTotal = "sizeTotal.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
          key_sizeAllocated = "sizeAllocated.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

          state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
          state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotal, timestampnow, one_object['content']['sizeTotal']))
          state_resources.append("%s %s %s %s" % (storage_name, key_sizeAllocated, timestampnow, one_object['content']['sizeAllocated']))
      elif ['pool'].count(resource) == 1:
        for one_object in resource_info['entries']:
          key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Use pull name instead lun id on zabbix key
          key_sizeUsedBytes = "sizeUsedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
          key_sizeTotalBytes = "sizeTotalBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
          key_sizeSubscribedBytes = "sizeSubscribedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

          state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
          state_resources.append("%s %s %s %s" % (storage_name, key_sizeUsedBytes, timestampnow, one_object['content']['sizeUsed']))
          state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotalBytes, timestampnow, one_object['content']['sizeTotal']))
          state_resources.append("%s %s %s %s" % (storage_name, key_sizeSubscribedBytes, timestampnow, one_object['content']['sizeSubscribed']))
      else:
        for one_object in resource_info['entries']:
          # Get state of resources from description
          descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Convert description to string
          if descriptionIds.find("ALRT_COMPONENT_OK") >= 0:
            running_status = 8
          elif descriptionIds.find("ALRT_DISK_SLOT_EMPTY") >= 0:
            running_status = 6
          else:
            running_status = 5

          key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
          key_status = "running.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
          state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
          state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, running_status))
  except Exception as oops:
    unity_logger.error("Error occured in get state")
    sys.exit("1000")

  api_session_logout = api_logout(api_ip, api_session)
  return send_data_to_zabbix(state_resources, storage_name)



def main() -> None:
  """
  Main function that initializes logging, parses arguments, and executes resource discovery or status retrieval.
  """
  # Setup logging
  global unity_logger
  log_level = logging.DEBUG
  log_format = "%(asctime)s - %(levelname)s - %(message)s"
  logging.basicConfig(stream=sys.stdout, format=log_format, level=log_level)
  unity_logger = logging.getLogger("unity_logger")

  # Parsing arguments
  unity_parser = argparse.ArgumentParser(description=__doc__)
  unity_parser.add_argument('--api_ip', action="store", help="Where to connect", required=True)
  unity_parser.add_argument('--api_port', action="store", required=True)
  unity_parser.add_argument('--api_user', action="store", required=True)
  unity_parser.add_argument('--api_password', action="store", required=True)
  unity_parser.add_argument('--storage_name', action="store", required=True)

  group = unity_parser.add_mutually_exclusive_group(required=True)
  group.add_argument('--discovery', action ='store_true')
  group.add_argument('--status', action='store_true')
  arguments = unity_parser.parse_args()

  list_resources = ['battery','ssd','ethernetPort','fcPort','sasPort','fan','powerSupply','storageProcessor','lun','pool','dae','dpe','ioModule','lcc','memoryModule','ssc','uncommittedPort','disk']
  if arguments.discovery:
    result_discovery = discovering_resources(arguments.api_user, arguments.api_password, arguments.api_ip, arguments.api_port, arguments.storage_name, list_resources)
    print (result_discovery)
  elif arguments.status:
    result_status = get_status_resources(arguments.api_user, arguments.api_password, arguments.api_ip, arguments.api_port, arguments.storage_name, list_resources)
    print (result_status)

if __name__ == "__main__":
  main()