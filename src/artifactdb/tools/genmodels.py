# runs on top instance's tools.admin script (yes, it's dirty)
# pylint: disable=wildcard-import,undefined-variable,unused-wildcard-import
import sys

from tools.admin import *
from artifactdb.db.elastic.convert import EsModelScript


def generate_models(output_file_tpl, clients=None, merge=False):
    clients = clients or mgr.schema_client.clients
    for client in  clients:
        output_filename = output_file_tpl.format(client.alias.replace("-","_"))
        print(f"Generating models for {client}")
        es_model_script = EsModelScript(client,output_filename,merge=merge)
        es_model_script.generate()


if __name__ == "__main__":
    OUTPUT_FILE_TPL = "db/elastic/models/gen_{}.py"
    if len(sys.argv) == 2:
        OUTPUT_FILE_TPL = sys.argv[-1]
    generate_models(OUTPUT_FILE_TPL)


