from aumbry import Attr
from .utils import PrintableYamlConfig


class SQLConfig(PrintableYamlConfig):
    """
    Config class for artifactdb.db.sql.client, roughly matching
    sqalchemy's create_engine() arguments
    """

    __mapping__ = {
        'database_host_url': Attr('database_host_url', str),
        'database_name': Attr('database_name', str),
        'database_user': Attr('database_user', str),
        'database_password': Attr('database_password', str),
        'database_driver': Attr('database_driver',str),
        'debug': Attr('debug',bool),
        'default_return_records':Attr('default_return_records',int)
    }
    database_host_url = None
    database_name = None
    database_user = None
    database_password = None
    database_drivername = None
    default_return_records = 10
    debug = False



