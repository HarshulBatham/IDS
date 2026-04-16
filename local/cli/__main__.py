# local/cli/__main__.py
"""
AeroGuard IDS - CLI Entry Point

Allows running CLI with: python -m local.cli [command] [options]
"""

from local.cli.commands import main

if __name__ == "__main__":
    main()
