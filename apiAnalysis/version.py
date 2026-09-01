"""Single source of truth for the application and public contract versions."""

__version__ = "0.2.0"
APP_NAME = "AuthCheck API Manager"
EXECUTION_CONTRACT_VERSION = "1"
IMPORT_CONTRACT_VERSION = "1"
RESULT_CONTRACT_VERSION = "1"


def version_info():
    return {
        "name": APP_NAME,
        "version": __version__,
        "contracts": {
            "import": IMPORT_CONTRACT_VERSION,
            "execution": EXECUTION_CONTRACT_VERSION,
            "result": RESULT_CONTRACT_VERSION,
        },
    }
