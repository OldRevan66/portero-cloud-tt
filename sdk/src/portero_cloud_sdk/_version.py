"""Versión del SDK. La fuente única es ``pyproject.toml``; aquí solo se lee del paquete
instalado, y viaja en el ``User-Agent`` (``portero-cloud-sdk/<versión>``)."""

from importlib.metadata import version

__version__ = version("portero-cloud-sdk")
