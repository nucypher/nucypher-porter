import click

from nucypher.config.constants import USER_LOG_DIR, DEFAULT_CONFIG_ROOT
from porter.main import BANNER


def echo_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.secho(BANNER, bold=True)
    ctx.exit()


def echo_logging_root_path(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.secho(str(USER_LOG_DIR.absolute()))
    ctx.exit()


def echo_config_root_path(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.secho(str(DEFAULT_CONFIG_ROOT.absolute()))
    ctx.exit()
