"""relay.ends -- the PROVIDER layer of Relay Mode.

Nothing in ``relay.kernel``, ``relay.state``, ``relay.effects``, ``relay.observe`` or
``relay.packets`` may import anything here. Endpoints are reached by NAME through
``relay.registry``, the same inversion ``executors.registry`` performs for Program Mode, so
"provider-neutral kernel" is a property a control can check by walking the import graph rather
than a claim in a docstring.
"""
from __future__ import annotations
