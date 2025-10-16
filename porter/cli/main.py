import click
from nucypher.blockchain.eth import domains
from nucypher.characters.lawful import Ursula
from nucypher.cli.config import group_general_config
from nucypher.cli.options import (
    option_domain,
    option_min_stake,
    option_registry_filepath,
    option_teacher_uri,
)
from nucypher.cli.types import NETWORK_PORT
from nucypher.cli.utils import get_registry, setup_emitter

from porter.cli.help import echo_config_root_path, echo_logging_root_path, echo_version
from porter.cli.literature import PORTER_CORS_ALLOWED_ORIGINS, PORTER_RUN_MESSAGE
from porter.main import BANNER, Porter


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
@option_domain(default=str(domains.DEFAULT_DOMAIN), validate=True, required=True)
@click.option(
    "--eth-endpoint",
    "eth_endpoint",
    help="Blockchain provider's URI i.e. 'file:///path/to/geth.ipc'",
    type=click.STRING,
    required=True,
)
@click.option(
    "--polygon-endpoint",
    "polygon_endpoint",
    help="Connection URL for Polygon chain",
    type=click.STRING,
    required=True,
)
@option_teacher_uri
@option_registry_filepath
@option_min_stake
@click.option(
    "--http-port",
    help="Porter HTTP/HTTPS port for JSON endpoint",
    type=NETWORK_PORT,
    default=Porter.DEFAULT_PORT,
)
@click.option(
    "--allow-origins",
    help="The CORS origin(s) comma-delimited list of strings/regexes for origins to allow - no origins allowed by default",
    type=click.STRING,
)
@click.option(
    "--dry-run",
    "-x",
    help="Execute normally without actually starting Porter",
    is_flag=True,
)
@click.option(
    "--eager",
    help="Start learning and scraping the domain before starting up other services",
    is_flag=True,
    default=True,
)
def run(
    general_config,
    domain,
    eth_endpoint,
    polygon_endpoint,
    teacher_uri,
    registry_filepath,
    min_stake,
    http_port,
    allow_origins,
    dry_run,
    eager,
):
    """Start Porter's Web controller."""
    emitter = setup_emitter(general_config, banner=BANNER)

    domain = domains.get_domain(domain)
    registry = get_registry(domain=domain, registry_filepath=registry_filepath)
    teacher = None
    if teacher_uri:
        teacher = Ursula.from_teacher_uri(
            teacher_uri=teacher_uri,
            min_stake=min_stake,
            registry=registry,
            eth_endpoint=eth_endpoint,
        )

    PORTER = Porter(
        domain=domain,
        known_nodes={teacher} if teacher else None,
        registry=registry,
        start_learning_now=eager,
        eth_endpoint=eth_endpoint,
        polygon_endpoint=polygon_endpoint,
    )

    emitter.message(f"TACo Domain: {str(PORTER.domain).capitalize()}", color="green")
    emitter.message(f"ETH Endpoint URI: {eth_endpoint}", color="green")
    emitter.message(f"Polygon Endpoint URI: {polygon_endpoint}", color="green")

    # firm up falsy status (i.e. change specified empty string to None)
    allow_origins = allow_origins if allow_origins else None
    # covert to list of strings/regexes
    allow_origins_list = None
    if allow_origins:
        allow_origins_list = allow_origins.split(",")  # split into list of origins to allow
        emitter.message(PORTER_CORS_ALLOWED_ORIGINS.format(allow_origins=allow_origins_list), color='green')

    controller = PORTER.make_web_controller(
        crash_on_error=False, cors_allow_origins_list=allow_origins_list
    )
    message = PORTER_RUN_MESSAGE.format(http_port=http_port)
    emitter.message(message, color='green', bold=True)
    return controller.start(port=http_port,
                            dry_run=dry_run)
