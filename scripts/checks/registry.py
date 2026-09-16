"""Import check modules so they register on FAST_CHECKS / SLOW_CHECKS.

Other agents add one line here after creating their module, for example:
    from . import packages  # noqa: F401

Order is first-seen category order in the panel.
"""

from . import plugins  # noqa: F401
from . import firewall  # noqa: F401
from . import kernel  # noqa: F401
from . import lsm  # noqa: F401
from . import privileges  # noqa: F401
from . import keys  # noqa: F401
from . import desktop  # noqa: F401
from . import network  # noqa: F401
from . import services  # noqa: F401
