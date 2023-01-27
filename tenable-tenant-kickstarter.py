"""
This is an example of how to execute the following steps:
1- Create a new Tenable.io evaluation tenant from the Tenable.io MSSP portal
2- Create a new API user in the new Tenable.io evaluation tenant
3- Generate API keys for the new API user and communicate those API keys back to the person/process running this script
"""

import configparser
import json
from urllib.parse import urlencode
from warnings import filterwarnings

from tenable.io import TenableIO

# pyTenable issues this warning on stateful requests. There is no issue, so we want to suppress this warning.
# https://github.com/tenable/pyTenable/blob/5157e061828d4db5601a8d62a690d1f58aeda9c7/tenable/base/platform.py#L170
filterwarnings('ignore', message=".*Starting an unauthenticated session.*")

# Identification
# https://developer.tenable.com/docs/user-agent-header
# UPDATE THIS INFORMATION
vendor = 'ACME'
product = 'FancyIntegration'
build = '1.0'

# Read in tenable.ini configuration file
config_file = 'tenable.ini'
config = configparser.ConfigParser()
config.read(config_file)
network_config = config['network']
ssl_verify = str.lower(network_config['ssl_verify'])
if ssl_verify == 'false':
    ssl_verify = False
else:
    ssl_verify = True
proxies = json.loads(network_config['proxies'])
mssp_config = config['tenable_io_mssp']
mssp_access_key = mssp_config['access_key']
mssp_secret_key = mssp_config['secret_key']
tenant_config = config['tenable_io_tenant']
tenant_registration_username = tenant_config['registration_username']
tenant_registration_region = tenant_config['registration_region']
tenant_custom_name = tenant_config['custom_name']
tenant_automation_username = tenant_config['automation_username']
tenant_automation_password = tenant_config['automation_password']
tenant_automation_user_group = tenant_config['automation_user_group']

# Create a new Tenable.io client for the MSSP portal
tio_mssp_client = TenableIO(
    vendor=vendor,
    product=product,
    build=build,
    access_key=mssp_access_key,
    secret_key=mssp_secret_key,
    ssl_verify=ssl_verify,
    proxies=proxies
)

# Create a new Tenable.io eval tenant
response = tio_mssp_client.post(
    'mssp/accounts/eval',
    json={
        "email": tenant_registration_username,
        "country": tenant_registration_region
    }
)

# Debugging
# print(response.status_code)

# Get the new tenant name
tenant_name = response.json()['name']

# Get the new tenant UUID and domain
response = tio_mssp_client.get('mssp/accounts')
for account in response.json()['accounts']:
    if account['container_name'] == tenant_name:
        tenant_uuid = account['uuid']
        tenant_domain = account['domains'][0]

# Apply a custom name to the new tenant
# NOTE: Each custom name must be unique. A duplicate custom name will result in an HTTP 409 error.
response = tio_mssp_client.patch(
    'mssp/accounts/' + tenant_uuid,
    json={"custom_name": tenant_custom_name}
)

# Now that the eval tenant is created, fetch a saml_response and saml_config_id
response = tio_mssp_client.post('mssp/accounts/' + tenant_uuid + '/login?domain=' + tenant_domain)

# Execute the SAML login
data = {'SAMLResponse': response.json()['saml_response']}
urlencode(data)
response = tio_mssp_client.post('saml/login/' + response.json()['saml_config_id'], data=data)

# Parse the SAML response
data = response.content.decode()
iron_token = data[56:120]
iron_samlurl = data[161:209]
iron_samlsuccess = data[254:258]

# Create a new Tenable.io client for the eval tenant
tio_tenant_client = TenableIO(
    vendor=vendor,
    product=product,
    build=build,
    access_key=None,
    secret_key=None,
    ssl_verify=ssl_verify,
    proxies=proxies
)
tio_tenant_client._session.headers.update({'X-Cookie': 'token=' + iron_token})

# Perform work in the new eval tenant
# Create an API user
response = tio_tenant_client.users.create(tenant_automation_username, tenant_automation_password, 64)
tenant_user_id = response['id']
tenant_uuid = response['container_uuid']

# Disable user/pass and SAML authentication for this user. Only allow API authentication for this user.
tio_tenant_client.users.edit_auths(tenant_user_id, True, False, False)

# Create an API user group
response = tio_tenant_client.groups.create(tenant_automation_user_group)
tenant_user_group_id = response['id']
tenant_user_group_uuid = response['uuid']
tenant_user_group_name = response['name']

# Add the API user to the API user group
tio_tenant_client.groups.add_user(tenant_user_group_id, tenant_user_id)

# Give the user group Can View and Can Scan permissions for All Assets
tio_tenant_client.v3.access_control.create(
    {
        "name": tenant_automation_user_group,
        "actions": ["CanView", "CanScan"],
        "subjects": [{"type": "UserGroup", "uuid": tenant_user_group_uuid, "name": tenant_user_group_name}],
        "objects": [{"type": "AllAssets"}]
    }
)

# Generate API keys for the API user
response = tio_tenant_client.users.gen_api_keys(tenant_user_id)
tenant_automation_access_key = response['accessKey']
tenant_automation_secret_key = response['secretKey']

# Terminate the stateful session
tio_tenant_client.post('mssp/accounts/logout')

# Build a dictionary with relevant information
result = {
    "uuid": tenant_uuid,
    "username": tenant_automation_username,
    "accessKey": tenant_automation_access_key,
    "secretKey": tenant_automation_secret_key
}

# Print relevant information to screen
print(
    '\nNew tenant details\n' +
    '------------------\n' +
    'UUID: ' + result['uuid'] + '\n' +
    'API username: ' + result['username'] + '\n' +
    'Access key: ' + result['accessKey'] + '\n' +
    'Secret key: ' + result['secretKey'] + '\n'
)
