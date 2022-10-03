# pylint: disable=redefined-outer-name,invalid-name
import sys
import getopt
import json
import pika


class ConsumerCallback:
    def __init__(self, fname, count):
        self.fname = fname
        self.count = count

    def __call__(self, channel, method, properties, body):
        print(f"Messages left: {self.count}")
        saved = {"properties": properties.__dict__, "body": body.decode("utf-8")}
        with open(self.fname, 'a') as fin:
            fin.write(json.dumps(saved))
            fin.write("\n")
        self.count = self.count - 1

        if self.count == 0:
            channel.stop_consuming()


class RabbitMQ:
    def __init__(self, user, password):
        self.credentials = pika.PlainCredentials(user, password)
        self.connection = None

    def __enter__(self):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq-headless', 5672, '/', self.credentials))
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.connection.close()


def declare_queue(channel, queue, priority):
    if not priority:
        return channel.queue_declare(queue = queue, durable = True)
    else:
        return channel.queue_declare(queue = queue, durable = True, arguments = {'x-max-priority': priority})


def restore_queue(file, queue, priority = None):
    print(f"Restore messages from file: '{file}' to queue: '{queue}'.")
    # TODO: take user/pass from config
    with RabbitMQ('user', 'abc123') as rmq:
        channel = rmq.connection.channel()
        _ = declare_queue(channel, queue, priority)

        with open(file) as fin:
            lines = fin.readlines()

        for line in lines:
            msg = json.loads(line)
            body = str.encode(msg['body'])
            properties = pika.spec.BasicProperties(**msg['properties'])
            channel.basic_publish(exchange = queue, routing_key=queue, body = body, properties=properties)


def backup_queue(queue, file, priority = None):
    print(f"Backup messages from queue: '{queue}' to file: '{file}'")
    with RabbitMQ('user', 'abc123') as rmq:
        channel = rmq.connection.channel()
        dqueue = declare_queue(channel, queue, priority)
        msg_count = dqueue.method.message_count

        if msg_count:
            callb = ConsumerCallback(file, msg_count)
            channel.basic_consume(queue=queue, auto_ack=True, on_message_callback=callb)
            channel.start_consuming()
        else:
            print("No messages to backup.")


if __name__ == "__main__":
    argv = sys.argv[1:]
    usage = 'Usage: python queues.py <--restore|--backup> -f <file> -q <queue> -p <priority>'

    try:
        opts, args = getopt.getopt(argv, "hf:q:p:q", ["file =", "queue =", "restore", "backup", "priority ="])
    except getopt.GetoptError:
        print(usage)
        sys.exit(2)

    file = None
    queue = None
    restore = False
    backup = False
    priority = None
    for opt, arg in opts:
        if opt == '-h':
            print(usage)
            sys.exit()
        elif opt in ("-f", "--file"):
            file = arg
        elif opt in ("-q", "--queue"):
            queue = arg
        elif opt in ("--restore"):
            restore = True
        elif opt in ("--backup"):
            backup = True
        elif opt in ("-p", "--priority"):
            priority = int(arg)

    if not (restore ^ backup and queue and file):
        print(usage)
        sys.exit(2)

    if backup:
        print("Please be sure no new messages will be send to the queue. New messages will not be saved.")
        input('Press enter to continue: ')
        backup_queue(queue, file, priority)
        sys.exit()

    if restore and queue and file:
        restore_queue(file, queue, priority)
        sys.exit()

