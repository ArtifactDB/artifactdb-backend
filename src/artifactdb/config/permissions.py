from aumbry import Attr
from .utils import PrintableYamlConfig


class PermissionsConfig(PrintableYamlConfig):
    __mapping__ = {
        'mandatory': Attr('mandatory', bool),
        'default_permissions': Attr('default_permissions',dict),
    }
    # if a project is indexed while no permissions could be found for it,
    # is this an error ? Yes, if mandatory is True. Otherwise, no permissions
    # are associated to that project (it would only be accesible by admins, or
    # permissions would be set later)
    mandatory = False
    default_permissions = {}  # default permissions template


