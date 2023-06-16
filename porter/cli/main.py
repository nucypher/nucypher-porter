import click
from nucypher.blockchain.eth.networks import NetworksInventory
from nucypher.characters.lawful import Ursula
from nucypher.cli.config import group_general_config
from nucypher.cli.options import (
    option_network,
    option_eth_provider_uri,
    option_teacher_uri,
    option_registry_filepath,
    option_min_stake
)
from nucypher.cli.types import NETWORK_PORT
from nucypher.cli.utils import setup_emitter, get_registry
from nucypher.config.constants import TEMPORARY_DOMAIN

from porter.cli.help import echo_version, echo_config_root_path, echo_logging_root_path
from porter.cli.literature import (
    PORTER_CORS_ALLOWED_ORIGINS,
    PORTER_RUN_MESSAGE
)
from porter.main import Porter, BANNER


@click.group()
@click.option('--version', help="Echo the CLI version",
              is_flag=True, callback=echo_version, expose_value=False, is_eager=True)
@click.option('--config-path', help="Echo the configuration root directory path",
              is_flag=True, callback=echo_config_root_path, expose_value=False, is_eager=True)
@click.option('--logging-path', help="Echo the logging root directory path",
              is_flag=True, callback=echo_logging_root_path, expose_value=False, is_eager=True)
def porter_cli():
    """Top level command for all things porter."""


@porter_cli.command()
@group_general_config
@option_network(default=NetworksInventory.DEFAULT, validate=True, required=False)
@option_eth_provider_uri(required=False)
@option_teacher_uri
@option_registry_filepath
@option_min_stake
@click.option('--http-port', help="Porter HTTP/HTTPS port for JSON endpoint", type=NETWORK_PORT, default=Porter.DEFAULT_PORT)
@click.option('--allow-origins', help="The CORS origin(s) comma-delimited list of strings/regexes for origins to allow - no origins allowed by default", type=click.STRING)
@click.option('--dry-run', '-x', help="Execute normally without actually starting Porter", is_flag=True)
@click.option('--eager', help="Start learning and scraping the network before starting up other services", is_flag=True, default=True)
def run(general_config,
        network,
        eth_provider_uri,
        teacher_uri,
        registry_filepath,
        min_stake,
        http_port,
        allow_origins,
        dry_run,
        eager):
    """Start Porter's Web controller."""
    emitter = setup_emitter(general_config, banner=BANNER)

    # HTTP/HTTPS
    if not eth_provider_uri:
        raise click.BadOptionUsage(option_name='--eth-provider',
                                   message=click.style("--eth-provider is required for decentralized porter.", fg="red"))
    if not network:
        # should never happen - network defaults to 'mainnet' if not specified
        raise click.BadOptionUsage(option_name='--network',
                                   message=click.style("--network is required for decentralized porter.", "red"))

    registry = get_registry(network=network, registry_filepath=registry_filepath)
    teacher = None
    if teacher_uri:
        teacher = Ursula.from_teacher_uri(teacher_uri=teacher_uri,
                                          min_stake=min_stake,
                                          registry=registry,
                                          provider_uri=eth_provider_uri)

    PORTER = Porter(domain=network,
                    known_nodes={teacher} if teacher else None,
                    registry=registry,
                    start_learning_now=eager,
                    eth_provider_uri=eth_provider_uri)

    emitter.message(f"Network: {PORTER.domain.capitalize()}", color='green')
    emitter.message(f"ETH Provider URI: {eth_provider_uri}", color='green')

    # firm up falsy status (i.e. change specified empty string to None)
    allow_origins = allow_origins if allow_origins else None
    # covert to list of strings/regexes
    allow_origins_list = None
    if allow_origins:
        allow_origins_list = allow_origins.split(",")  # split into list of origins to allow
        emitter.message(PORTER_CORS_ALLOWED_ORIGINS.format(allow_origins=allow_origins_list), color='green')

    controller = PORTER.make_web_controller(crash_on_error=False,
                                            cors_allow_origins_list=allow_origins_list)
    message = PORTER_RUN_MESSAGE.format(http_port=http_port)
    emitter.message(message, color='green', bold=True)
    return controller.start(port=http_port,
                            dry_run=dry_run)
