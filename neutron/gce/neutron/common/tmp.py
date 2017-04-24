import gceutils
compute = gceutils.get_gce_service('/etc/neutron/omni.json')
project = 'omni-163105'
region = 'asia-east1'

# operation = gceutils.create_network(compute, project, 'pvt')
# gceutils.wait_for_operation(compute, project, operation)
#
# network = gceutils.get_network(compute, project, 'pvt')
# network_link = network['selfLink']
# operation = gceutils.create_subnet(compute, project, region, 'pvtsub',
#                                    '192.168.1.0/24', network_link)
# gceutils.wait_for_operation(compute, project, operation)
#
# operation = gceutils.delete_subnet(compute, project, region, 'pvtsub')
# gceutils.wait_for_operation(compute, project, operation)
#
# operation = gceutils.delete_network(compute, project, 'pvt')
# gceutils.wait_for_operation(compute, project, operation)

operation = gceutils.create_static_ip(compute, project, region, 'instanceip')
gceutils.wait_for_operation(compute, project, operation)

address = gceutils.get_static_ip(compute, project, region, 'instanceip')
print(address)

operation = gceutils.delete_static_ip(compute, project, region, 'instanceip')
gceutils.wait_for_operation(compute, project, operation)
