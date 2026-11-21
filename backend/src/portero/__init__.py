"""Portero Cloud: sistema de gestión de secretos para equipos de desarrollo de PyMEs.

Monolito modular en capas (Cap. 5, diagrama de componentes):
``api`` → servicios (``auth``, ``rbac``, ``secrets_mgmt``, ``management``, ``oplog``)
→ ``db.repositories`` → ``db.models``. Solo ``secrets_mgmt`` y ``auth`` usan ``crypto``.
"""
