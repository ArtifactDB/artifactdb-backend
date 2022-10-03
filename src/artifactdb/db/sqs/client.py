import json
from urllib.parse import urlparse, parse_qs

import boto3


class SQSClient:

    def __init__(self, sqs_cfg, create=False,**access_params):
        self.batch_size = sqs_cfg.batch_size
        self.access_params = access_params
        self.name = sqs_cfg.arn.split(':')[-1] if sqs_cfg.arn else sqs_cfg.name
        assert self.name, "SQS config must specify either an `arn` or queue `name`"
        self._resource = boto3.resource("sqs",**self.access_params)
        self._client = boto3.client("sqs",**self.access_params)
        if create:
            res = self._client.create_queue(QueueName=self.name)
            assert res["ResponseMetadata"]["HTTPStatusCode"] == 200
        self.queue = self._resource.get_queue_by_name(QueueName=self.name)
        self.attrs = self._fetch_attributes()

    def delete(self):
        self._client.delete_queue(QueueUrl=self.attrs["QueueUrl"])

    def consume(self):
        total = 0
        while True:
            msgs = list(self.queue.receive_messages(MaxNumberOfMessages=self.batch_size))
            if not msgs:
                break
            total += self.process(msgs)
        return total

    def process(self, msgs):
        count = 0
        while msgs:
            msg = msgs.pop()
            self.dispatch(msg)
            msg.delete()  # ack
            count += 1
        return count

    def extract(self, msg):
        """
        Return (subscription_arn,payload) from msg
        Payload is taken from msg.body, and parsed as JSON
        """
        # extract ARN from unsubscribe URL, as there's no dedicated field
        payload = json.loads(msg.body)
        parsed = urlparse(payload["UnsubscribeURL"])
        sub_arn = parse_qs(parsed.query)["SubscriptionArn"][0]
        return sub_arn,payload

    def dispatch(self, msg):
        raise NotImplementedError("implement me in subclass")

    def get_sqs_policy(self):
        strpolicy = self.attrs.get("Policy")
        if strpolicy:
            policy = json.loads(strpolicy)
        else:
            policy = self._generate_sqs_base_policy()

        return policy

    def set_sqs_policy(self, policy):
        self._client.set_queue_attributes(QueueUrl=self.queue.url,Attributes={"Policy":json.dumps(policy)})

    def _whoami(self):
        sts =  boto3.client("sts",**self.access_params)
        return sts.get_caller_identity()

    def _generate_sqs_base_policy(self):
        # base, some sort of a template. Content taken from what AWS
        # sets when doing that manually from the web console
        user = self._whoami()
        policy = {
            'Version': '2008-10-17',
            'Id': '__default_policy_ID',
            'Statement': [
                {
                    'Sid': '__receiver_statement',
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': user["Arn"],
                    },
                    'Action': [
                        'SQS:ChangeMessageVisibility',
                        'SQS:DeleteMessage',
                        'SQS:ReceiveMessage'
                    ],
                }
            ]
        }

        return policy

    def _fetch_attributes(self):
        # fetch all attributes to get the ARN
        res = self._client.get_queue_attributes(QueueUrl=self.queue.url,AttributeNames=["All"])
        assert res["ResponseMetadata"]["HTTPStatusCode"] == 200, res
        attrs = res["Attributes"]
        # for consistency, put url here as well (it's not in original AWS response)
        attrs["QueueUrl"] = self.queue.url
        return attrs



