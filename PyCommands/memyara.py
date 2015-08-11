#------------------------------------------------------------------------------
# Memory Yara
#
# Runs Yara rules over a given address range
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

import yara

from immlib import Debugger


__VERSION__ = '1.00'
NAME = 'memyara'
DESC = 'Run Yara rules over a memory range or loaded module'


def usage(imm):
    """Display the usage.

    Args:
        imm: Immunity debugger object
    """

    imm.log(' ')
    imm.log('!%s [-m module] -r /path/to/rules start-address end-address' % \
            NAME)
    imm.log('    -h                : Display this message')
    imm.log('    -m module         : Module name')
    imm.log('    -r /path/to/rules : Path to Yara rules file')
    imm.log('    start-address     : Start address')
    imm.log('    end-address       : End address')
    imm.log('ex: !%s -r /path/to/rules 40000000 80000000' % NAME)
    imm.log('ex: !%s -m kernel32 -r /path/to/rules' % NAME)
    imm.log(' ')


def _display_results(imm, matches):
    """Display results from the Yara matches in a table.

    Args:
        imm: Immunity debugger object
        matches: List of Yara matches
    """
    table = imm.createTable('Yara matches',
                            ['Rule', 'Offset', 'Identifier', 'Offset'])

    for match in matches:
        table.add(0, [match.rule, '%ld' % match.strings[0], match.strings[1],
                      match.strings[2]])


def run_yara_on_module(imm, module_name, rules):
    """Run Yara over a module loaded in memory. The results are displayed in
    the log window.

    Args:
        imm: Immunity debugger object
        module_name: Name of the module to run the Yara rules over
        rules: Compiled Yara rules

    Returns:
        String describing the success/failure of the operation
    """

    if module_name.split('.')[-1] not in ('exe', 'sys', 'dll'):
        module_name = '%s.dll' % module_name

    module = imm.getModule(module_name)

    if not module:
        return '%s is not a loaded module' % module_name

    # Run Yara rules over the module
    data = imm.readMemory(module.getBaseAddress(), module.getSize())
    matches = rules.match(data=data)
    _display_results(imm, matches)

    return '%d matches' % len(matches)


def run_yara_on_address_range(imm, start_addr, end_addr, rules):
    """Run Yara over a given address range. The results are displayed in the
    log window.

    Args:
        imm: Immunity debugger object
        start_addr: Start address
        end_addr: End address
        rules: Compiled Yara rules

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

    # Run Yara rules over the memory range
    data = imm.readMemory(start_addr, end_addr - start_addr)
    matches = rules.match(data=data)
    _display_results(imm, matches)

    return '%d matches' % len(matches)


def main(args):
    """The main function.

    Args:
        args: Command-line arguments
    """

    imm = Debugger()
    module = None
    rules_file = None

    try:
        opts, args = getopt.getopt(args, 'hm:r:')
    except getopt.GetoptError:
        usage(imm)
        return 'Incorrect arguments (check log window)'

    for opt, arg in opts:
        if opt == '-h':
            usage(imm)
            return ''
        elif opt == '-m':
            module = arg
        elif opt == '-r':
            rules_file = arg

    if not rules_file:
        usage(imm)
        return 'Incorrect arguments (Path to Yara rule file required)'

    # Compile the Yara rules
    try:
        rules = yara.compile(filepath=rules_file)
    except (yara.YaraSyntaxError, yara.YaraError):
        return '%s is an invalid Yara rules file' % rules_file

    if module:
        return run_yara_on_module(imm, module, rules)
    elif len(args) == 2:
        return run_yara_on_address_range(imm, args[0], args[1], rules)
    else:
        usage(imm)
        return 'Incorrect arguments (check log window)'
