"""
Copyright (c) 2018 Platform9 Systems Inc.
All Rights reserved
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


from nova import cache_utils

_VM_REFS_CACHE = cache_utils.get_client()


def vm_ref_cache_delete(id):
    global _VM_REFS_CACHE
    _VM_REFS_CACHE.delete(id)


def vm_ref_cache_get(id):
    global _VM_REFS_CACHE
    return _VM_REFS_CACHE.get(id)


def vm_ref_cache_update(id, item):
    global _VM_REFS_CACHE
    value = vm_ref_cache_get(id)
    if value:
        vm_ref_cache_delete(id)
    _VM_REFS_CACHE.add(id, item)
