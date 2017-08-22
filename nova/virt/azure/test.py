import os
import sys
import utils

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

compute_client = utils.get_compute_client(tenant_id, client_id, client_secret, subscription_id)
out = utils.list_instances(compute_client, resource_group)
for i in out:
    print(i)
