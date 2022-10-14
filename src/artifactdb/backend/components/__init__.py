# pylint: disable=invalid-name
from abc import ABC, ABCMeta, abstractmethod, abstractproperty


class InvalidComponentError(Exception): pass
class ComponentNotFoundError(Exception): pass


BACKEND_METHOD_TAG = "_backend_method"
def managermethod(method, name=None):
    """
    Decorator used by backend components to register method in the manager
    by binding and patching the manager instance, making the `method`
    *as if* the method was part of the manager.
    """
    setattr(method,BACKEND_METHOD_TAG,method.__name__ if name is None else name)
    return method


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

    def component_init(self):
        """
        Optional init step called once the component instance was created
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



class WrappedBackendComponent(BackendComponent):
    """
    Add wrapper function to transparently convert an external object
    into a backend component.
    The wrapped instance must be stored in self.wrapped, in init()
    """

    def __init__(self, manager, cfg):
        self.manager = manager
        self.main_cfg = cfg  # the whole config
        self.cfg = None  # placholder for the component config section
        self._wrapped = self.wrapped()
        assert not self._wrapped is None, "wrapped() must return the wrapped instance, got None"

    @abstractmethod
    def wrapped(self):
        """
        Return the instance the backend component should wrap.
        """

    def __getattr__(self, name):
        if name == "_wrapped":
            return self._wrapped
        else:
            return getattr(self._wrapped,name)

