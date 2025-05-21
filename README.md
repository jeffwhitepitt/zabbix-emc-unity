# zabbix-emc-unity

Python script that collects hardware health metrics (disks, power supplies, ports, etc.), pool capacity, and LUN usage from EMC Unity storage via REST API and sends them to Zabbix for monitoring.

## Requirements

- Python 3
- zabbix-sender

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Set these macros in "Template EMC Unity REST-API":

- {$API_USER}
- {$API_PASSWORD}
- {$API_PORT}
- {$SUBSCRIBED_PERCENT}
- {$USED_PERCENT}

Set **ServerActive=xxx.xxx.xxx.xxx** in **/etc/zabbix/zabbix_agentd.conf**.

Copy the script to zabbix-server or zabbix-proxy.

## Usage

Run discovery:

```bash
./unity_get_state.py --api_ip=xxx.xxx.xxx.xxx --api_port=443 --api_user=username --api_password='password' --storage_name="storage-host-name-in-zabbix" --discovery
```

This discovery should run periodically.

Reload cache:

```bash
zabbix_proxy -R config_cache_reload
```

or

```bash
zabbix_server -R config_cache_reload
```

Collect metrics:

```bash
./unity_get_state.py --api_ip=xxx.xxx.xxx.xxx --api_port=443 --api_user=username --api_password='password' --storage_name="storage-name" --status
```

This collect should run periodically.

## Troubleshooting

Ensure zabbix user has read/write access to **/tmp/unity_state.log**.

Return codes 1 or 2 are from zabbix_sender. See [here](https://www.zabbix.com/documentation/4.4/manpages/zabbix_sender).
