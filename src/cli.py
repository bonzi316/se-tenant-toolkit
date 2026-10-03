import click
import logging
import sys
from src.config import load_config
from src.client import get_zscaler_client, load_env_file
from src.zcc import setup_zcc
from src.zia import setup_zia
from src.zpa import setup_zpa
from src.exporter import export_zcc_presets, export_zia_presets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("src")

@click.group()
def cli():
    """Zscaler Proof of Concept (POV) Tenant Preparation Tool."""
    pass

@cli.command()
@click.option("--config", "-c", default="pov_preset.yaml", help="Path to the POV preset YAML configuration file.")
@click.option("--dry-run", is_flag=True, help="Validate and simulate the tenant preparation without making API updates.")
@click.option("--prefix", "-p", default="", help="Prefix to prepend to all created ZIA policy/category names.")
@click.option("--env-file", "-e", required=True, help="Path to the custom environment file (e.g. customer.env).")
@click.option("--rule-label", default=None, help="Rule label to automatically attach to all created ZIA rules.")
def prep(config, dry_run, prefix, env_file, rule_label):
    """Prepares and configures a Zscaler tenant for POV using a YAML configuration."""
    # Load custom env file if specified
    load_env_file(env_file)
    click.echo(f"=== Starting Zscaler POV Tenant Prep (Dry-Run: {dry_run}) ===")
    
    try:
        # 1. Load and Validate config
        logger.info(f"Loading configuration file: {config}")
        pov_config = load_config(config)
        logger.info("Configuration file is valid.")
        
        # 2. Initialize and authenticate client
        client = get_zscaler_client()
        
        # 3. Setup configurations
        overall_results = {}
        
        if pov_config.zcc:
            click.echo("\n--- Configuring Zscaler Client Connector (ZCC) ---")
            overall_results["zcc"] = setup_zcc(client, pov_config.zcc, dry_run=dry_run)
            
        if pov_config.zia:
            click.echo("\n--- Configuring Zscaler Internet Access (ZIA) ---")
            import os
            config_dir = os.path.dirname(os.path.abspath(config))
            overall_results["zia"] = setup_zia(client, pov_config.zia, dry_run=dry_run, prefix=prefix, config_dir=config_dir, rule_label=rule_label)
            
        if pov_config.zpa:
            click.echo("\n--- Configuring Zscaler Private Access (ZPA) ---")
            overall_results["zpa"] = setup_zpa(client, pov_config.zpa, dry_run=dry_run)
            
        click.echo("\n=== Tenant Preparation Complete ===")
        # Print summary
        for product, res in overall_results.items():
            click.echo(f"\n{product.upper()} Configuration Summary:")
            if not res:
                click.echo("  No changes made.")
            else:
                for k, v in res.items():
                    if isinstance(v, list):
                        click.echo(f"  {k}:")
                        for item in v:
                            click.echo(f"    - {item}")
                    else:
                        click.echo(f"  {k}: {v}")
                        
    except Exception as e:
        click.echo(f"\n[ERROR] Tenant preparation failed: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.option("--product", type=click.Choice(["zcc", "zia", "all"]), default="all", help="Zscaler product to export presets for.")
@click.option("--query", "-q", default=None, help="Filter profile names matching this search query.")
@click.option("--output", "-o", default="pov_preset_exported.yaml", help="Path to save the exported YAML configurations.")
@click.option("--env-file", "-e", required=True, help="Path to the custom environment file (e.g. customer.env).")
def export(product, query, output, env_file):
    """Exports configuration presets from a Zscaler tenant to a YAML file."""
    # Load custom env file if specified
    load_env_file(env_file)
    click.echo(f"=== Exporting Zscaler Configurations to {output} ===")
    
    try:
        # Initialize and authenticate client
        client = get_zscaler_client()
        
        if product in ["zcc", "all"]:
            click.echo("Exporting ZCC settings...")
            export_zcc_presets(client, search_query=query, out_path=output)
            
        if product in ["zia", "all"]:
            click.echo("Exporting ZIA settings...")
            export_zia_presets(client, out_path=output)
            
        click.echo(f"\nExport complete. Configurations saved to: {output}")
        
    except Exception as e:
        click.echo(f"\n[ERROR] Export failed: {e}", err=True)
        sys.exit(1)

if __name__ == "__main__":
    cli()
