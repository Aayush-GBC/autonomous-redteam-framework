"""
ARTASF package entry point.

Allows the framework to be invoked as a module:
    python -m artasf          →  artasf --help
    python -m artasf run ...  →  full pipeline
    python -m artasf scan ... →  recon only
"""

from artasf.ui.cli import main

if __name__ == "__main__":
    main()
