from abc import ABC, abstractmethod

from artifactdb.backend.components import BackendComponent


class RevisionError(Exception): pass


class RevisionBase:

    # Example. Note: it's recommanded to prefix the revision with a string,
    # so it's not just an integer, as there could be confusion with the "version"
    # if it's also just an integer
    PREFIX = "REVISION-"

    def __init__(self,rev):
        """
        Create a revision object from "rev", which can either be a
        straight integer, or a prefixed revision following class' PREFIX
        pattern.
        """
        if isinstance(rev,str) and rev.lower() == "latest":
            raise RevisionError("'{}' is reserved revision".format(rev))
        try:
            self.rev = int(rev)
        except ValueError:
            # check correct prefix
            if not rev.startswith(self.__class__.PREFIX):
                raise RevisionError("Revision must start with: '{}'".format(self.__class__.PREFIX))
            self.rev = int(rev.replace(self.__class__.PREFIX,""))

    def __str__(self):
        return self.__class__.PREFIX + "{}".format(self.rev)

    def __repr__(self):
        return "<{}.{}: {} [{}]>".format(self.__module__,self.__class__.__name__,str(self),int(self))

    def __int__(self):
        return self.rev

    def to_dict(self):
        return {
            "revision": str(self),
            "numerical_revision": int(self),
        }


# Simple revision provider
class NumericalRevision(RevisionBase):

    PREFIX = "NUM-"


class RevisionProviderBase(ABC):

    def __init__(self, es_manager):
        self.es_manager = es_manager

    @abstractmethod
    def get_next_revision(self, project_id):
        """
        Given a project ID, scan the versions and associated
        revisions and return a RevisionBase object corresponding the next
        revision that should be used if a new version is created
        """
        raise NotImplementedError("implement me in sub-class")


class NumericalRevisionProvider(RevisionProviderBase):

    def get_next_revision(self, project_id):
        latest = self.es_manager.find_latest_revision(project_id)
        if latest is None:
            latest = 0
        return self.create_revision(latest+1)

    def create_revision(self, revision):
        return NumericalRevision(revision)


class SimpleRevisionProvider(NumericalRevisionProvider):

    def create_revision(self, revision):
        return RevisionBase(revision)


class RevisionManagerBase:

    provider = None

    def __init__(self, provider_klass, es_manager):
        if not self.__class__.provider:
            self.__class__.provider = provider_klass(es_manager)

    def __getattr__(self, name):
        if name == "provider":
            return self.provider
        else:
            return getattr(self.provider, name)


class RevisionManager(BackendComponent, RevisionManagerBase):

    NAME = "revision_manager"
    FEATURES = ["revisions",]
    DEPENDS_ON = ["es",]

    def __init__(self, manager, cfg, provider_klass=None):
        provider_klass = provider_klass if provider_klass else NumericalRevisionProvider
        RevisionManagerBase.__init__(self,provider_klass,manager.es)

    def __getattr__(self, name):
        if name == "provider":
            return self.provider
        else:
            return getattr(self.provider, name)


