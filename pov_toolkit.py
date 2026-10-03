#!/usr/bin/env python3

import click
import logging
import sys
import os
from src.config import load_config, POVConfig
from src.client import get_zscaler_client, load_env_file
from src.zcc import setup_zcc
from src.exporter import export_zcc_presets, export_zia_presets, export_zpa_presets
from src.zia import setup_zia
from src.zpa import setup_zpa

def filter_dict_by_scopes(data: dict, scopes: list) -> tuple:
    """Filters a nested dictionary to only keep keys matching the specified dotted path scopes."""
    if not scopes:
        return data, set()

    # Normalize scopes
    normalized_scopes = [s.strip().lower() for s in scopes]
    matched_scopes = set()

    def is_path_allowed(current_path_str: str) -> bool:
        if current_path_str == "version":
            return True
        allowed = False
        for scope in normalized_scopes:
            if current_path_str == scope or current_path_str.startswith(scope + "."):
                matched_scopes.add(scope)
                allowed = True
            elif scope.startswith(current_path_str + "."):
                allowed = True
        return allowed

    def recurse(obj, current_path: list):
        path_str = ".".join(current_path)
        
        for scope in normalized_scopes:
            if path_str == scope or path_str.startswith(scope + "."):
                matched_scopes.add(scope)
                import copy
                return copy.deepcopy(obj)

        if isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                next_path = current_path + [k.lower()]
                next_path_str = ".".join(next_path)
                if is_path_allowed(next_path_str):
                    filtered_val = recurse(v, next_path)
                    if filtered_val is not None:
                        new_dict[k] = filtered_val
            return new_dict
        else:
            return obj

    filtered_data = recurse(data, [])
    return filtered_data, matched_scopes


@click.command()
@click.option(
    "--config",
    "-c",
    default="configs/pov_preset.yaml",
    help="Path to the POV preset configuration YAML file.",
    show_default=True,
)
@click.option(
    "--dry-run",
    "-d",
    is_flag=True,
    help="Perform a dry run without making actual API changes.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose debug logging.",
)
@click.option(
    "--export-zcc",
    is_flag=True,
    help="Export ZCC configuration (Profiles, Networks, Privacy, Cleanup) from the tenant to a YAML file.",
)
@click.option(
    "--export-zia",
    is_flag=True,
    help="Export ZIA configuration (URL Categories, Settings, Profile, Security) from the tenant to a YAML file.",
)
@click.option(
    "--export-zpa",
    is_flag=True,
    help="Export ZPA configuration (Connector Groups, Server Groups, Segment Groups, App Segments, Policies) from the tenant to a YAML file.",
)
@click.option(
    "--search",
    default=None,
    help="Search query to filter forwarding and application profiles by name when exporting.",
)
@click.option(
    "--export-out",
    default="pov_preset_exported.yaml",
    help="Output file path for the exported YAML configuration.",
    show_default=True,
)
@click.option(
    "--prefix",
    "-p",
    default="POV-TOOL",
    help="Prefix dynamically added to the names of created/updated objects during deployment (default: POV-TOOL). Set to empty string '' to deploy without prefix.",
    show_default=True,
)
@click.option(
    "--env-file",
    "-e",
    required=True,
    help="Path to environment file (e.g. .env.zdemo-users)",
)
@click.option(
    "--rule-label",
    default=None,
    help="Rule label to automatically attach to all created ZIA rules.",
)
@click.option(
    "--activate",
    "-a",
    is_flag=True,
    help="Activate ZIA configuration changes after applying",
)
@click.option(
    "--scope",
    multiple=True,
    help="Scope specific configuration sections to apply (e.g., zcc.app_profiles, zia.url_filtering_rules). Can be specified multiple times.",
)
def main(config, dry_run, verbose, export_zcc, export_zia, export_zpa, search, export_out, prefix, env_file, activate, scope, rule_label):
    # Set logging level
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Configure handlers to output to stdout and logs/src.log
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join("logs", "src.log"), encoding="utf-8")
    ]
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=handlers
    )
    
    # Configure Zscaler SDK logger to only output warnings/errors during a standard run,
    # and debug/info when verbose logging is enabled.
    zscaler_logger = logging.getLogger("zscaler")
    if verbose:
        zscaler_logger.setLevel(logging.DEBUG)
    else:
        zscaler_logger.setLevel(logging.WARNING)

    logger = logging.getLogger("src")
    
    # Load custom env file if specified
    load_env_file(env_file)
    
    logger.info("Starting Zscaler POV Tenant Preparation Tool (ZCC Focus)...")
    if dry_run:
        logger.info("RUNNING IN DRY-RUN MODE - No changes will be written to the tenant.")

    # 1. Load configuration (skip if only exporting and config file is missing/default)
    pov_config = None
    try:
        logger.info(f"Loading configuration from: {config}")
        pov_config = load_config(config)
        logger.info("Configuration loaded and validated successfully.")
        
        # Apply scope filtering if scope is specified
        if scope:
            logger.info(f"Applying scope filter: {list(scope)}")
            config_dict = pov_config.model_dump(exclude_none=True)
            filtered_dict, matched_scopes = filter_dict_by_scopes(config_dict, list(scope))
            
            unmatched = set(s.strip().lower() for s in scope) - matched_scopes
            if unmatched:
                logger.warning(f"The following scopes did not match any configuration elements: {list(unmatched)}")
                
            # Log what we've kept
            kept_sections = []
            for top_level in ["zcc", "zia", "zpa"]:
                if top_level in filtered_dict and filtered_dict[top_level]:
                    sub_keys = list(filtered_dict[top_level].keys())
                    kept_sections.append(f"{top_level}: {sub_keys}")
            logger.info(f"Filtered config sections to apply: {', '.join(kept_sections)}")
            
            pov_config = POVConfig.model_validate(filtered_dict)
            
    except Exception as e:
        # If exporting, it's fine if the preset config file doesn't exist
        if not (export_zcc or export_zia or export_zpa):
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
        else:
            logger.info("Config load bypassed or failed for exporter execution flow.")

    # 2. Authenticate Zscaler Client
    try:
        client = get_zscaler_client()
    except Exception as e:
        logger.error(f"Failed to authenticate Zscaler client: {e}")
        sys.exit(1)

    # Exporter execution flow
    if export_zcc or export_zia or export_zpa:
        try:
            if export_zcc:
                export_zcc_presets(client, search_query=search, out_path=export_out)
            if export_zia:
                export_zia_presets(client, out_path=export_out)
            if export_zpa:
                export_zpa_presets(client, out_path=export_out)
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error during export: {e}")
            sys.exit(1)

    # 3. Setup ZIA
    if pov_config and pov_config.zia:
        try:
            logger.info("Starting ZIA configurations setup...")
            config_dir = os.path.dirname(os.path.abspath(config))
            results_zia = setup_zia(client, pov_config.zia, dry_run=dry_run, prefix=prefix, config_dir=config_dir, rule_label=rule_label)
            logger.info(f"ZIA configurations completed. Results: {results_zia}")
        except Exception as e:
            logger.error(f"Error during ZIA setup: {e}")
            sys.exit(1)
    else:
        logger.info("No ZIA configuration found in the preset.")

    # 4. Setup ZCC
    if pov_config and pov_config.zcc:
        try:
            logger.info("Starting ZCC configurations setup...")
            results = setup_zcc(client, pov_config.zcc, dry_run=dry_run, prefix=prefix)
            logger.info(f"ZCC configurations completed. Results: {results}")
        except Exception as e:
            logger.error(f"Error during ZCC setup: {e}")
            sys.exit(1)
    else:
        logger.info("No ZCC configuration found in the preset.")

    # 5. Setup ZPA
    if pov_config and pov_config.zpa:
        try:
            logger.info("Starting ZPA configurations setup...")
            results_zpa = setup_zpa(client, pov_config.zpa, dry_run=dry_run)
            logger.info(f"ZPA configurations completed. Results: {results_zpa}")
        except Exception as e:
            logger.error(f"Error during ZPA setup: {e}")
            sys.exit(1)
    else:
        logger.info("No ZPA configuration found in the preset.")

    # 6. Activation
    if pov_config and pov_config.zia and activate and not dry_run:
        logger.info("Activating ZIA Configuration...")
        try:
            _, _, err = client.zia.activate.activate()
            if err:
                logger.error(f"ZIA Activation failed: {err}")
            else:
                logger.info("ZIA configuration activated successfully.")
        except Exception as e:
            logger.error(f"Error activating ZIA configuration: {e}")

    logger.info("POV preparation run completed.")

def preprocess_argv():
    """Helper to automatically restore empty string arguments for -p/--prefix options
    which are stripped by PowerShell's command line parser before reaching Python."""
    import sys
    new_args = []
    i = 0
    while i < len(sys.argv):
        arg = sys.argv[i]
        new_args.append(arg)
        if arg in ('-p', '--prefix'):
            if i + 1 < len(sys.argv):
                next_arg = sys.argv[i + 1]
                # If next argument looks like an option (e.g. starts with '-' and next char is a letter)
                if next_arg.startswith('-') and len(next_arg) > 1 and next_arg[1].isalpha():
                    new_args.append('')
            else:
                new_args.append('')
        i += 1
    sys.argv = new_args

if __name__ == "__main__":
    preprocess_argv()
    main()
