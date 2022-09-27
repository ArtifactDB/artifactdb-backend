# pylint: disable=invalid-name
from abc import ABC, ABCMeta, abstractmethod, abstractproperty


class InvalidComponentError(Exception):
    pass

class BackendComponent(metaclass=ABCMeta):
    """
    Base class for backend sub-component
    """

    @abstractmethod
    def __init__(self, manager, cfg):
        """
        Instantiate the sub-component. `manager` is the backend manager instance
        being built, and `cfg` is the whole configuration object.
        If the sub-component creation is not possible (eg. missing or invalid configuration)
        an `InvalidComponentError` exception must be raised. It's up to the caller (backend manager
        being built) to decide whether the failure can be ignored (optional component) or not.
        """

    @property
    @abstractproperty
    def DEPENDS_ON(self):
        """
        List of other component names this component depends on.
        Currently informative only, but may be used in the future to resolve
        dependencies and help building backend manager more easily.
        """

    @property
    @abstractproperty
    def NAME(self):
        """
        Name of the backend component. Will be used to set a corresponding
        attribute in the backend manager.
        """

    @property
    @abstractproperty
    def FEATURES(self):
        """
        List of features the component provides to the backend.
        """




