import click

from porter.cli import porter
from porter.cli.help import echo_version, echo_config_root_path, echo_logging_root_path


@click.group()
@click.option('--version', help="Echo the CLI version",
              is_flag=True, callback=echo_version, expose_value=False, is_eager=True)
@click.option('--config-path', help="Echo the configuration root directory path",
              is_flag=True, callback=echo_config_root_path, expose_value=False, is_eager=True)
@click.option('--logging-path', help="Echo the logging root directory path",
              is_flag=True, callback=echo_logging_root_path, expose_value=False, is_eager=True)
def porter_cli():
    """Top level command for all things porter."""


ENTRY_POINTS = (
    porter.porter,      # Network support services
)

for entry_point in ENTRY_POINTS:
    porter_cli.add_command(entry_point)
