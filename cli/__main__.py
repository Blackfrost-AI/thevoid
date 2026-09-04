#!/usr/bin/env python3
"""THE VOID — module entry point.

Allows running ``python3 -m cli`` as an alias for the ``thevoid`` console script.
"""

from cli.app import main

if __name__ == "__main__":
    main()
