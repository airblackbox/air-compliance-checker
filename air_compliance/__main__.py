"""Allow running as `python -m air_compliance`."""
import sys
from air_compliance.cli import main

sys.exit(main())