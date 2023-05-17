import warnings
import copy

from aumbry import Attr

from .utils import PrintableYamlConfig, init_model
from .switches import Switch


class SequenceClient(PrintableYamlConfig):
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
        'test': Attr('test',bool),
        'debug': Attr('debug', bool),
        'context': Attr('context',str),
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
    # indicates that this sequence prefix should be used for tests purpose
    test = False
    # upon creation/init, should a provisioned pool be automatically created?
    # this is useful (True) for test environment, for prod environment,
    # it's recommended to go through an init from s3
    auto_create_pool = False
    # sqlalchemy echo statements
    debug = False
    # context name, to associate given client to a switch. If None, the client is allowed to be considered
    # even if a switch context is set (ie. sort of default, catch-all client)
    context = None

    def init_from(self, conf):
        for name, attr in self.__mapping__.items():
            try:
                value = conf[name]
                assert isinstance(value,attr.type)
                setattr(self,name,value)
            except KeyError:
                if attr.required:
                    raise

# Renamed for consistency, but maintain backward compat.
SequenceConfig = SequenceClient


class SequencesConfig(PrintableYamlConfig):
    __mapping__ = {
        "clients": Attr("clients",list),
        "switch": Attr("switch",Switch)
    }
    clients = []  # list of SequenceClient

    def to_dict(self, *args, **kwargs):
        oned = super().to_dict(*args,**kwargs)
        oned.pop("__clients__",None)  # was a copy of original, no need to expose
        return oned


def set_sequence_models(cfg):
    if cfg.sequence:
        warnings.warn(
            "Legacy `sequence` section found, use `sequences` (see adb.config.sequences.SequencesConfig)",
            DeprecationWarning
        )
        assert not cfg.sequences.clients, "Found a mix `sequences` and `sequence` config section"
        cfg.sequences.clients = cfg.sequence
    clients = []
    for seqcfg in cfg.sequences.clients:
        cfgobj = init_model(SequenceConfig,seqcfg)
        assert cfgobj.uri and cfgobj.project_prefix, "Sequence initialization error, conf: {}".format(seqcfg)
        clients.append(cfgobj)
    # replace with instantiated config model
    cfg.sequences.__clients__ = copy.deepcopy(cfg.sequences.clients)
    cfg.sequences.clients = clients

    return cfg

