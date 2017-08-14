"""
Copyright (c) 2017 Platform9 Systems Inc.
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from nova.compute import power_state

OMNI_STATE_MAP = {
    "PROVISIONING": power_state.NOSTATE,
    "STAGING": power_state.NOSTATE,
    "RUNNING": power_state.RUNNING,
    "STOPPING": power_state.NOSTATE,
    "SUSPENDING": power_state.NOSTATE,
    "SUSPENDED": power_state.SHUTDOWN,
    "TERMINATED": power_state.CRASHED
}

OMNI_ID = 'azure_id'

"""
Provisioning State  Description
Creating    Indicates the virtual Machine is being created.
Updating    Indicates that there is an update operation in progress on the Virtual Machine.
Succeeded   Indicates that the operation executed on the virtual machine succeeded.
Deleting    Indicates that the virtual machine is being deleted.
Failed      Indicates that the update operation on the Virtual Machine failed.

Power State     Description
Starting    Indicates the virtual machine is being started from the Hypervisor standpoint.
Running     Indicates that the virtual machine is being started from the Hypervisor standpoint.
Stopping    Indicates that the virtual machine is being stopped from the Hypervisor standpoint.
Stopped     Indicates that the virtual machine is stopped from the Hypervisor standpoint. Note that virtual machines in the stopped state still incur compute charges.
Deallocating    Indicates that the virtual machine is being deallocated from the Hypervisor standpoint.
Deallocated     Indicates that the virtual machine is removed from the Hypervisor standpoint but still available in the control plane. Virtual machines in the Deallocated state do not incur compute charges.
--  Indicates that the power state of the virtual machine is unknown.
"""
