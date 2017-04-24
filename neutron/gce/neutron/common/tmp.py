import gceutils
compute = gceutils.get_gce_service('/etc/neutron/omni.json')
project = 'omni-163105'
region = 'us-central1'
zone = 'us-central1-c'

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

floatingip = gceutils.allocate_floatingip(compute, project, region)
fixedip = '192.168.1.15'
print(floatingip)
gceutils.assign_floatingip(compute, project, zone, fixedip, floatingip)
print('Enter (y) verified')
raw_input()
gceutils.release_floatingip(compute, project, region, floatingip)
gceutils.delete_floatingip(compute, project, region, floatingip)

