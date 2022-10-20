import logging

from kombu.common import Broadcast
from kombu import Exchange, Queue

from artifactdb.backend.components import WrappedBackendComponent


DEFAULT_TASK_PRIORITY = 2
MAX_TASK_PRIORITY = 10


class QueuesError(Exception):
    pass


class QueuesManagerComponent(WrappedBackendComponent):

    NAME = "queues"
    FEATURES = ["queues","priority-queues"]
    DEPENDS_ON = []

    def wrapped(self):
        return QueuesManager(self.main_cfg.celery, self.manager.celery_app)


class QueuesManager:

    def __init__(self, cfg_celery, celery_app):
        self.celery_app = celery_app
        self.cfg = cfg_celery
        self.default_queue = None
        self.default_broadcast_queue = None
        self.queue_names = []
        self.broadcast_names = []

    @property
    def max_priority(self):
        """
        Enable max. priority if `queues` is defined in the configuration.
        Otherwise, there's no specific priority range.
        """
        return MAX_TASK_PRIORITY if self.cfg.get('queues') else None

    @property
    def default_priority(self):
        """
        Enable default priority if `queues` is defined in the configuration.
        Otherwise, there's no specific priority range.
        """
        return DEFAULT_TASK_PRIORITY if self.cfg.get('queues') else None

    def prepare_queues(self):
        """
        This method needs to be called once the Celery app is created,
        so the queue manager can access Celery config
        """
        q_settings = self.cfg.get('queues')
        if q_settings:
            logging.info(f"Applying queue settings: {q_settings}")
            self.check_settings(q_settings)
            queues = self._prepare_queues_and_set_defaults(q_settings)
            self.set_default_queue(self.default_queue)
            self.set_task_queues(queues)
        else:
            logging.info("Applying default queue settings")
            self.define_no_settings_queues()

    def check_settings(self, q_settings):
        default_count = 0
        default_broadcast_count = 0
        for qset in q_settings:
            default = qset.get('default')
            broadcast = qset.get('broadcast')
            if default and not broadcast:
                default_count += 1
            if default and broadcast:
                default_broadcast_count += 1
        if default_count != 1:
            raise QueuesError("Exactly one default queue should be in Celery settings.")
        if default_broadcast_count != 1:
            raise QueuesError("Exactly one default broadcast queue should be in Celery settings.")

    def _prepare_queues_and_set_defaults(self, q_settings):
        qlist = []
        for qset in q_settings:
            name = qset['name']
            default = qset.get('default')
            broadcast = qset.get('broadcast')
            if broadcast:
                queue = self.create_broadcast_queue(name,default=default)
            else:
                queue = self.create_queue(name,default=default)
            qlist.append(queue)

        return tuple(qlist)

    def define_no_settings_queues(self):
        default_queue_name = self.celery_app.conf.task_default_queue
        queues = (
            self.create_queue(default_queue_name),
            self.create_broadcast_queue('broadcast_tasks')
        )
        self.set_task_queues(queues)

    def create_broadcast_queue(self, name, exchange=None, default=None):
        if not exchange:
            exchange = name
        self.broadcast_names.append(name)
        if default:
            self.default_broadcast_queue = name

        return Broadcast(name, exchange=Exchange(exchange, type='fanout'))

    def create_queue(self, name, default=None):
        logging.debug(f"Creating queue {name} with priority {self.max_priority}")
        queue_kw = {'x-max-priority': self.max_priority} if self.max_priority else {}
        queue = Queue(name, Exchange(name), routing_key=name, queue_arguments=queue_kw)
        self.queue_names.append(name)
        if default:
            self.default_queue = name

        return queue

    def set_default_queue(self, name):
        self.celery_app.conf.task_default_queue = name

    def set_task_queues(self, queues):
        self.celery_app.conf.task_queues = queues

    def get_active_queues(self):
        ins = self.celery_app.control.inspect()
        active_qs = ins.active_queues()
        qdict = {}
        for key in active_qs:
            qdict[key] = list(map(lambda q: q['name'], active_qs[key]))

        return qdict

    def get_max_prorities(self):

        def get_max_priority(queue):
            if queue.queue_arguments and 'x-max-priority' in queue.queue_arguments:
                return queue.queue_arguments['x-max-priority']

        task_queues = self.celery_app._conf['task_queues']

        return [{"name":q.name, "max_priority": get_max_priority(q)} for q in task_queues]

