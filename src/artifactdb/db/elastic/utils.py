# pylint: disable=invalid-unary-operand-type  # weird elastic-py DSL notations
import logging

from elasticsearch_dsl import Search, Q

from artifactdb.rest.auth import AuthenticatedUser, AnonymousUser, RootUser
from artifactdb.utils.context import auth_user_context, skip_auth_context
from . import AUTH_FIELDS, NotAllowedException


def parse_q(q, index_name):
    """
    Return a dict representing ES query expressed in 'q':
    Ex: q="HAL OR project_id:GPA2"
    """
    query = Search(index=index_name).query("query_string",query=q)
    return query

def escape_query_param(param):
    """
    Escape special chars in query parameter `param`. A single
    string is expected for that parameter, not the full query string.
    """
    # case with ":" (GPRNs contain colons)
    param = param.replace(":",r'\:')
    return param

def parse_fields(query, fields):
    if fields:
        if isinstance(fields,str):
            fields = [fields]
        all_fields = list(set(fields).union(set(AUTH_FIELDS)))
        query = query.source(includes=all_fields)
    return query


def get_auth_user_ad_info():
    """Assuming an auth context is set, return list of viewers"""
    # we must have a auth user context
    auth_user = auth_user_context.get()
    if not auth_user:
        raise NotAllowedException("No user context found")

    # but maybe no DLs information (very unlikely though
    dls = set(auth_user.distribution_lists)
    ad_groups = set(auth_user.active_directory_groups)
    # anyone matching that list can view, either directly through
    # a UnixID or indirectly via a DL
    ids = set()
    if auth_user.unixID:
        ids.add(auth_user.unixID)
    viewers = list(ids.union(dls).union(ad_groups))

    return viewers


def authorize_query(q_obj, index_name=None):
    """
    Add query elements to q_obj to inject and implement authorization
    during query time. It interprets the value found in _extra.permissions.read_access:
    - "owners": people listed in _extra.permissions.owners are allowed to access data.
    - "viewers": people listed in _extra.permissions.viewers, or listed in
                 _extra.permissions.owners, are allowed to access the data. An owner
                 has at least the permissions of a viewer.
    - "authenticated": as long as the user is properly authenticated, data access is granted
    - "public": data can be accessed to anyone, even if not authenticated.

    Critical code. You've been warned.
    """

    skip_auth = skip_auth_context.get()
    current_user = auth_user_context.get()
    if skip_auth:
        logging.info("For user '{}', skipping auth, query is: {}".format(current_user,q_obj.to_dict()))
        return q_obj

    if isinstance(q_obj,str):
        assert index_name, "'index_name' is required to build a query object"
        q_obj = parse_q(q_obj,index_name)


    unixid_dls = get_auth_user_ad_info()

    def auth_q_owners():
        """
        check unixID or DLs found in "owners" field *if* read_access
        rule is "owners"
        """
        owners = {"_extra.permissions.owners": unixid_dls}
        access_rule = {"_extra.permissions.read_access": "owners"}
        return Q("terms",**owners) & Q("term",**access_rule)

    def auth_q_viewers():
        """
        Same as auth_q_owners() but for "viewers". Also include
        "owners", considered as also viewers.
        """
        viewers = {"_extra.permissions.viewers": unixid_dls}
        owners = {"_extra.permissions.owners": unixid_dls}
        access_rule = {"_extra.permissions.read_access": "viewers"}
        return (Q("terms",**owners) | Q("terms",**viewers)) & Q("term",**access_rule)

    def auth_q_authenticated():
        """
        Allows to check for access rule read_access=authenticated *if*
        user is authenticated.
        """
        # match_all if authenticated or math_none is not
        # rule is in a "OR", so it's not literally match all/none
        # it's more "consider other filters, or I'm out, don't count on me"
        # note: check the "~" before the Q, it means "not" in ES DSL so !match_all == match_none
        is_authenticated = Q('match_all') if isinstance(current_user, AuthenticatedUser) else ~Q('match_all')
        access_rule = {"_extra.permissions.read_access": "authenticated"}
        return is_authenticated & Q("term",**access_rule)

    def auth_q_anonymous():
        """
        Allows to check for access rule read_access=public if no authenticated
        user (anonymous/guest) or auth user found. Auth'd users have at least the
        same permissions as an anonymous.
        """
        anon_or_authed = isinstance(current_user, (AnonymousUser, AuthenticatedUser))
        is_anonymous = Q("match_all") if anon_or_authed else ~Q("match_all")
        access_rule = {"_extra.permissions.read_access": "public"}
        return is_anonymous & Q("term",**access_rule)


    if isinstance(current_user,RootUser):
        # skip terms query to filter data, we return everything
        auth_q = q_obj
    else:
        qowners = auth_q_owners()
        qviewers = auth_q_viewers()
        qauthed = auth_q_authenticated()
        qanon = auth_q_anonymous()  # not sure about that variable name...
        # check if any auth'd query matches some access rules (OR)
        auth_q = q_obj.query(qowners | qviewers | qauthed | qanon)
        #import json; print(json.dumps(auth_q.to_dict()))

    return auth_q
