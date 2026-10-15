import traceback

from pycti import OpenCTIConnectorHelper

from connector import ConnectorSettings, DocToStixConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,  # the bundle always holds the enriched entity
        )
        DocToStixConnector(config=settings, helper=helper).run()
    except Exception:
        traceback.print_exc()
        exit(1)
