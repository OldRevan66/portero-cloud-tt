"""SDK Python de Portero Cloud (CU-04; Cap. 6 §Diseño del SDK Python).

Lectura de secretos con el PAT de una Aplicación Cliente::

    from portero_cloud_sdk import PorteroClient

    with PorteroClient(base_url=os.environ["PORTERO_BASE_URL"],
                       token=os.environ["PORTERO_TOKEN"]) as client:
        client.validate()
        password = client.get_secret_value("Tienda en línea", "development", "DB_PASSWORD")

``PorteroAsyncClient`` tiene la misma firma, con corutinas y ``async with``.
"""

from portero_cloud_sdk._async import PorteroAsyncClient
from portero_cloud_sdk._sync import PorteroClient
from portero_cloud_sdk._version import __version__
from portero_cloud_sdk.errors import (
    AuthenticationError,
    NetworkError,
    PermissionDenied,
    PorteroError,
    RateLimited,
    SecretNotFound,
    ServerError,
)
from portero_cloud_sdk.models import Secret

__all__ = [
    "AuthenticationError",
    "NetworkError",
    "PermissionDenied",
    "PorteroAsyncClient",
    "PorteroClient",
    "PorteroError",
    "RateLimited",
    "Secret",
    "SecretNotFound",
    "ServerError",
    "__version__",
]
