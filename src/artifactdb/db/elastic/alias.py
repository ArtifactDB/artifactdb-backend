import os
import logging


CREATE_ALIAS = "CREATE_ALIAS"
REMOVE_ALIAS = "REMOVE_ALIAS"
REMOVE_INDEX = "REMOVE_INDEX"
OUT_OF_SYNC = "out-of-sync"
MISSING = "missing"
SYNCED = "synced"


class UpdateIndicesException(Exception): pass
class ForbiddenAliasOperation(Exception): pass


def _get_current_index(aliases, alias):
    for key in aliases:
        if alias in aliases[key]['aliases'].keys():
            return key

    return None


def _get_alias_prefix(clients):
    names = []
    for client in clients:
        if client.get("alias"):
            names.append(client["alias"])
    prefix = "{}*".format(os.path.commonprefix(names))

    return prefix


def _prepare_move_alias_changes_for_client(client, cfg, to_date):
    frontend = cfg.es.frontend.clients
    prefix = _get_alias_prefix(frontend.values())
    # filter with explicit alias names (not index names) as all aliases
    # are supposed to exist before moving them
    aliases = client.indices.get_alias(name=prefix)
    indices = aliases.keys()
    chg_list = []
    for key in frontend:
        if not isinstance(frontend[key],dict):
            continue
        alias = frontend[key]['alias']
        target_index = f"{alias}-{to_date}"
        if not target_index in indices:
            raise UpdateIndicesException(f"Can't find target index '{target_index}'")
        current_index = _get_current_index(aliases, alias)
        chg_list.append({
            'type': REMOVE_ALIAS,
            'index': current_index,
            'alias': alias
        })
        chg_list.append({
            'type': CREATE_ALIAS,
            'index': target_index,
            'alias': alias
        })

    return chg_list


def _prepare_alias_changes_for_client(es_client, cfg, ops):
    client = es_client.client
    frontend = cfg.es.frontend.clients
    backend = cfg.es.backend.clients
    prefix = _get_alias_prefix(frontend.values())
    # filter by index names, as some aliases may or may not exists
    # but we still need the index names in order to create them
    aliases = client.indices.get_alias(index=prefix)
    indices = aliases.keys()
    chg_list = []
    for key in frontend:
        if key != es_client.alias:
            continue  # not matching our client
        alias = frontend[key]['alias']
        if backend[key] and backend[key]['index']:
            index = backend[key]['index']
        else:
            raise UpdateIndicesException(f"Key: '{key}' not defined correctly in backend es settings.")
        if alias == index:
            continue
        if alias in indices:
            raise UpdateIndicesException(f"Removing the index: '{alias}' is necessary. Check the config file or remove it manually.")
        # good to go and proceed
        current_index = _get_current_index(aliases, alias)
        if current_index != index:
            if current_index:
                chg_list.append({
                    'type': REMOVE_ALIAS,
                    'index': current_index,
                    'alias': alias
                })
            chg_list.append({
                'type': CREATE_ALIAS,
                'index': index,
                'alias': alias
            })
        for unnecessary in aliases[index]['aliases']:
            if unnecessary != alias:
                chg_list.append({
                    'type': REMOVE_ALIAS,
                    'index': index,
                    'alias': unnecessary
                })
    # verify we can do the operations we found
    forbiddens = {_["type"] for _ in chg_list}.difference(set(ops))
    if forbiddens:
        raise ForbiddenAliasOperation(f"Operation not allowed: {forbiddens}")

    return chg_list


def _prepare_alias_changes(clients, cfg, ops):
    chg_list = []
    for key in clients:
        try:
            changes = _prepare_alias_changes_for_client(clients[key],cfg,ops)
        except ForbiddenAliasOperation as e:
            logging.warning(f"Forbidden alias operation for client {key}, skip it: {e}")
            continue
        for chg in changes:
            if not any(cc["type"] == chg["type"] and cc["alias"] == chg["alias"] and cc["index"] == chg["index"] for cc in chg_list):
                chg_list.append(chg)

    return chg_list


def _prepare_move_alias_changes(clients, cfg, to_date):
    chg_list = []
    for key in clients:
        changes = _prepare_move_alias_changes_for_client(clients[key].client, cfg, to_date)
        for chg in changes:
            if not any(cc["type"] == chg["type"] and cc["alias"] == chg["alias"] and cc["index"] == chg["index"] for cc in chg_list):
                chg_list.append(chg)

    return chg_list


def _agreement_for_aliases(chg_list, ask=True):
    logging.info("Following operation for aliases will be applied:")
    for _op in chg_list:
        if _op['type'] == CREATE_ALIAS:
            logging.info("Creating alias: '{}' for index: '{}'".format(_op['alias'], _op['index']))
        elif _op['type'] == REMOVE_INDEX:
            raise ForbiddenAliasOperation(f"Operation not allowed: {_op}")
        elif _op['type'] == REMOVE_ALIAS:
            logging.info("Removing alias: '{}' for index: '{}'".format(_op['alias'], _op['index']))

    if ask:
        logging.info("Are you sure you want to modify and update indices configuration? [y/N]")
        choice = input().lower()
        return choice in ["y", "yes"]

    return True


def _apply_changes(chg_list, client):
    actions = []

    for chg in chg_list:
        if chg['type'] == CREATE_ALIAS:
            actions.append({
                'add': {
                    'index': chg['index'],
                    'alias': chg['alias']
                }
            })
        elif chg['type'] == REMOVE_ALIAS:
            actions.append({
                'remove': {
                    'index': chg['index'],
                    'alias': chg['alias']
                }
            })
    client.client.indices.update_aliases({"actions": actions})


def _perform_alias_changes(chgs, client, ask=True):
    if chgs:
        if not _agreement_for_aliases(chgs,ask=ask):
            logging.info("Abort")
            return
        else:
            _apply_changes(chgs, client)
            logging.info("Updates applied.")
    else:
        logging.info("Nothing to change. Aliases are up to date.")


################
# MAIN HELPERS #
################

def update_es_aliases(clients, cfg, ops=(CREATE_ALIAS,REMOVE_ALIAS), ask=True):
    chgs = _prepare_alias_changes(clients,cfg,ops)
    key = list(clients.keys())[0]  # pick one ES client, it can access any indices/aliases
    _perform_alias_changes(chgs,clients[key],ask=ask)


def move_es_alias(clients, cfg, to_date):
    """
    Move aliases to indices with `to_date` as suffix. The indices names
    before moving the aliases are taken from clients and cfg.
    """
    chgs = _prepare_move_alias_changes(clients, cfg, to_date)
    key = list(clients.keys())[0]  # to select an ES client, whatever it is, it has access to all indices
    _perform_alias_changes(chgs,clients[key])

