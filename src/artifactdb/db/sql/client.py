from sqlalchemy import create_engine

from artifactdb.config import init_model
from artifactdb.config.sql import SQLConfig


class SqlClient:

    def __init__(self, config_file=None, **params):
        """
        Init a SQL client either from config object and kw params
        """
        self.cfg = config_file or init_model(SQLConfig,params)
        host_url = self.cfg.database_host_url
        db_user = self.cfg.database_user
        db_password = self.cfg.database_password
        db_name = self.cfg.database_name
        db_driver = self.cfg.database_driver
        self.uri = f"{db_driver}://{db_user}:{db_password}@{host_url}/{db_name}"
        self.engine = create_engine(self.uri, echo=self.cfg.debug)

    def execute(self, *args, **kwargs):
        return self.engine.execute(*args,**kwargs)

    def __repr__(self):
        return "<{}: host={},db={}>".format(self.__class__.__name__,self.cfg.database_host_url,self.cfg.database_name)
