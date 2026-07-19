"""Allow ``python -m lamd`` to behave like the ``lamd`` console command."""

from .cli import main

raise SystemExit(main())
