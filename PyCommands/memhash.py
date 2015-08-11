#------------------------------------------------------------------------------
# Memory Hash
#
# Calculates an MD5 sum of a given address range
#
# Copyright (c) 2015 Adrian Herrera
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#------------------------------------------------------------------------------

import getopt
from hashlib import md5

from immlib import Debugger
from pefile import PE


__VERSION__ = '1.00'
NAME = 'memhash'
DESC = 'Hash a memory range or loaded module'


def usage(imm):
    """Display the usage.

    Args:
        imm: Immunity debugger object
    """

    imm.log(' ')
    imm.log('!%s [-m module] start-address end-address' % NAME)
    imm.log('    -h            : Display this message')
    imm.log('    -m module     : Module name')
    imm.log('    start-address : Start address')
    imm.log('    end-address   : End address')
    imm.log('ex: !%s 40000000 80000000' % NAME)
    imm.log('ex: !%s -m kernel32' % NAME)
    imm.log(' ')


def hash_module(imm, module_name):
    """Calculate an MD5 hash of each section in a given module. The results are
    displayed in the log window.

    Args:
        imm: Immunity debugger object
        module_name: Name of the module to hash

    Returns:
        String describing the success/failure of the operation
    """

    if module_name.split('.')[-1] not in ('exe', 'sys', 'dll'):
        module_name = '%s.dll' % module_name

    module = imm.getModule(module_name)

    if not module:
        return '%s is not a loaded module' % module_name

    pe = PE(name=module.getPath())

    for section in pe.sections:
        section_name = section.Name.split('\x00')[0]
        start = module.getBaseAddress() + section.VirtualAddress
        virtual_size = section.Misc_VirtualSize
        alignment = pe.OPTIONAL_HEADER.SectionAlignment
        size = virtual_size + (alignment - virtual_size % alignment)

        data = imm.readMemory(start, size)
        md5sum = md5(data).hexdigest()

        imm.log('%s %s MD5: %s' % (module.name, section_name, md5sum))

    return 'Calculated hash for %s' % module.name


def hash_address_range(imm, start_addr, end_addr):
    """Calculate an MD5 hash of a given address range. The results are
    displayed in the log window.

    Args:
        imm: Immunity debugger object
        start_addr: Start address
        end_addr: End address

    Returns:
        String describing the success/failure of the operation
    """

    try:
        start_addr = int(start_addr, 16)
    except ValueError:
        usage(imm)
        return 'Invalid start address (0x%s)' % start_addr

    try:
        end_addr = int(end_addr, 16)
    except ValueError:
        usage(imm)
        return 'Invalid end address (0x%s)' % end_addr

    if start_addr is None or end_addr is None:
        usage(imm)
        return 'Start and end addresses must be specified'
    if start_addr >= end_addr:
        usage(imm)
        return 'End address must be greater than start address'

    # Calculate MD5 sum of memory range
    data = imm.readMemory(start_addr, end_addr - start_addr)
    md5sum = md5(data).hexdigest()

    # Print results
    imm.log('0x%08x - 0x%08x MD5: %s' % (start_addr, end_addr, md5sum))

    return 'Calculated hash for 0x%08x - 0x%08x' % (start_addr, end_addr)


def main(args):
    """The main function.

    Args:
        args: Command-line arguments
    """

    imm = Debugger()
    module = None

    try:
        opts, args = getopt.getopt(args, 'hm:')
    except getopt.GetoptError:
        usage(imm)
        return 'Incorrect arguments (check log window)'

    for opt, arg in opts:
        if opt == '-h':
            usage(imm)
            return ''
        if opt == '-m':
            module = arg

    if module:
        return hash_module(imm, module)
    elif len(args) == 2:
        return hash_address_range(imm, args[0], args[1])
    else:
        usage(imm)
        return 'Incorrect arguments (check log window)'
