from aumbry import Attr
from .utils import PrintableYamlConfig


class SequenceConfig(PrintableYamlConfig):
    __mapping__ = {
        'uri': Attr('uri',str),
        'db_user': Attr('db_user',str),
        'db_password': Attr('db_password',str),
        'schema_name': Attr('schema_name',str),
        'project_prefix': Attr('project_prefix',str),
        'project_format': Attr('project_format',str),
        'max_sequence_id': Attr('max_sequence_id',int),
        'version_first': Attr('version_first',str),
        'auto_create_pool': Attr('auto_create_pool',bool),
        'default': Attr('default',bool),
        'debug': Attr('debug', bool),
    }
    uri = None
    db_user = None
    db_password = None
    schema_name = None
    project_prefix = "ADB"
    # prefix is custom prefix or project_prefix
    # seq_id is a unique sequence number
    # f-string is eval'd assuming these variable as set
    project_format = '''f"{prefix}{seq_id}"'''
    # max identifier for projects
    max_sequence_id = 999999999
    # what value for the first version in a new project
    version_first = "1"
    # if no prefix is specified, should that client be the default one
    default = False
    # upon creation/init, should a provisioned pool be automatically created?
    # this is useful (True) for test environment, for prod environment,
    # it's recommended to go through an init from s3
    auto_create_pool = False
    # sqlalchemy echo statements
    debug = False

    def init_from(self, conf):
        for name, attr in self.__mapping__.items():
            try:
                value = conf[name]
                assert isinstance(value,attr.type)
                setattr(self,name,value)
            except KeyError:
                if attr.required:
                    raise


