import azutils as utils
import os
import sys

def abort(message):
    sys.exit(message)

def get_env_param(env_name):
    if env_name in os.environ:
        return os.environ[env_name]
    abort("%s environment variable not set." % env_name)

tenant_id = get_env_param('AZURE_TENANT_ID')
client_id = get_env_param('AZURE_CLIENT_ID')
client_secret = get_env_param('AZURE_CLIENT_SECRET')
subscription_id = get_env_param('AZURE_SUBSCRIPTION_ID')
region = get_env_param('AZURE_REGION')
resource_group = 'omni_resource_group'

network = utils.get_network_client(tenant_id, client_id, client_secret,
                                   subscription_id)
network_name = 'test-network'
subnet_name = 'test-subnet'
print("Create network")
body = {
    'location': region,
    'address_space': {
        'address_prefixes': ['10.0.1.0/24', '10.0.2.0/24']
    }
}
utils.create_network(network, resource_group, network_name, body)
print(utils.get_network(network, resource_group, network_name))
utils.create_subnet(network, resource_group, network_name, subnet_name,
                    {'address_prefix': '10.0.1.0/24'})
print(utils.get_subnet(network, resource_group, network_name, subnet_name))
utils.delete_subnet(network, resource_group, network_name, subnet_name)
print("Delete network")
utils.delete_network(network, resource_group, network_name)
