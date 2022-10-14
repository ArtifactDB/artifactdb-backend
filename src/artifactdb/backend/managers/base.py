# pylint: disable=no-member  # manager gets patched with members from components registration
# pylint: disable=unused-argument  # args no used but could be useful for context when inheriting
import inspect

import logging

from artifactdb.backend.components import InvalidComponentError, ComponentNotFoundError, BACKEND_METHOD_TAG, \
                                          BackendComponent


class BackendManagerBase:

    # Backend components can be added using build(...) method # or declared here,
    # as a list of {"class": path.to.component.Class, "required": bool}
    COMPONENTS = []
    # map of components instances, created from the definition above
    REGISTERED = []

    def __init__(self, cfg, celery_app=None):
        self.cfg = cfg
        self.celery_app = celery_app
        #self._proxied = {}  # hold proxied/patched methods from components (see __getattr__)
        self.register_components()

    def build(self, component_class, required=None):
        if hasattr(self,component_class.NAME):
            raise InvalidComponentError(f"Backend component {component_class.NAME!r} already added")
        try:
            component_inst = component_class(self,self.cfg)
            # register the instance as the component's name
            logging.info(f"Adding backend component {component_class.NAME!r}")
            setattr(self,component_class.NAME,component_inst)
            return component_inst
        except InvalidComponentError as exc:
            # build arg has precedence over the component re: required
            is_required = required if not required is None else component_class.REQUIRED
            if not is_required:
                logging.warning(f"Backend component {component_class} can't be created, but ignored " + \
                                f"(not required): {exc}")
            else:
                raise

    def patch_backend_methods(self, component_mod):
        for something in component_mod.__dict__.values():
            method_name = getattr(something,BACKEND_METHOD_TAG,None)
            if method_name:
                logging.debug(f"Patching manager instance with component {component_mod.__name__!r} method {something}")
                # bind to manager instance
                bound = something.__get__(self,self.__class__)  # pylint: disable=unnecessary-dunder-call
                setattr(self.__class__,method_name,bound)

    def register_components(self):
        """
        Iterate over COMPONENTS list and register them using build(...) method
        """
        built_components = self.build_components()
        for component in self.__class__.COMPONENTS:
            self.patch_backend_methods(component["module"])
        _ = [comp.component_init() for comp in built_components]

    def build_components(self):
        registered = []
        for component in self.__class__.COMPONENTS:
            builts = self.build_component(component)
            logging.debug(f"{len(builts)} component(s) built from {component}")
            registered.extend(builts)
        return registered

    def build_component(self, component):

        classes_found = []
        def pred(something):
            # we're looking for: a component class, defined in the module (not from imports)
            # and that is not a aliased class (renamed for backwarc compat)
            if inspect.isclass(something) and issubclass(something,BackendComponent) and something.__module__ == component["module"].__name__:
                not_found_before = something not in classes_found
                if not_found_before:
                    classes_found.append(something)
                return not_found_before

        registered = []
        for _,cls in inspect.getmembers(component["module"],predicate=pred):
            component_inst = self.build(
                component_class=cls,
                required=component["required"]
            )
            if component_inst is None:
                continue  # non-required component + built failed
            # in-place, keep track of actual component class
            component["class"] = cls
            registered.append(component_inst)

        return registered

    @classmethod
    def replace_component(cls, module_name, **component_kwargs):
        found = None
        for (i,_) in enumerate(cls.COMPONENTS):
            if _.get("module") and _["module"].__name__ == module_name:
                found = i
                break
        if found is None:
            raise ComponentNotFoundError(module_name)
        cls.COMPONENTS[found] = component_kwargs

