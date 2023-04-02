from simics import *

cli.quiet_run_command('bp.console_string.break object = board.serconsole.con string = FAILED')
cli.quiet_run_command('bp.console_string.break object = board.serconsole.con string = Exception')
cli.quiet_run_command('bp.console_string.break object = board.serconsole.con string = ASSERT')

