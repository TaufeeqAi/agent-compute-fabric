"""The credential in use, and the agent credentials it minted.

An agent is an untrusted caller even when its developer trusts it, so an agent is given a credential of
its own: narrower than the developer's, shorter-lived, and labelled. This module mints, lists and
revokes those.

Minting and revoking change the platform's own records and reach no host. They carry no idempotency
key. That has one consequence worth knowing: a mint whose answer is lost may have created a credential
whose secret nobody saw. It is found by listing, and revoked.

Revoking ends what a credential may ask for. It does not end what the credential already started, and
the platform cancels nothing by itself. ``contain=True`` is the client doing that: it revokes, then
cancels every execution the credential started that has not ended.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Final

from agentcompute import _keys
from agentcompute._resources import cancel_execution, target_identifier
from agentcompute._transport import Engine, Flow, Request, encode, identifier, page_items, segment
from agentcompute._units import flag, seconds, text
from agentcompute.errors import APIConnectionError, FabricError, UnexpectedResponseError
from agentcompute.types import AgentCredential, ContainmentFailure, Operation, WhoAmI, has_ended

if TYPE_CHECKING:
    from agentcompute._binding import AsyncBinder, SyncBinder

__all__ = ["AsyncAuth", "Auth"]

_COLLECTION: Final = "/agent-credentials"
_EXECUTION_TYPE: Final = "execution.create"


def whoami(engine: Engine) -> Flow[WhoAmI]:
    """The calling credential's principal, project and effective grants."""
    answer = yield from engine.perform(Request("GET", "/v1/auth/whoami"))
    return WhoAmI(answer.body, request_id=answer.request_id)


def _mint(
    engine: Engine, label: str, lifetime: int | str, narrowing: Mapping[str, Any] | None
) -> Flow[AgentCredential]:
    body: dict[str, Any] = {
        "label": text(label, what="label"),
        "lifetime_seconds": seconds(lifetime, what="lifetime"),
    }
    if narrowing is not None:
        if not isinstance(narrowing, Mapping):
            raise ValueError("narrowing must be a mapping: a grant, as the API describes it")
        body["narrowing"] = dict(narrowing)
    payload = encode(body)
    path = (yield from engine.project_path()) + _COLLECTION
    try:
        # Not repeatable: without a key, a second request that follows a received one mints a second credential.
        answer = yield from engine.perform(Request("POST", path, body=payload, repeatable=False))
    except (APIConnectionError, UnexpectedResponseError) as error:
        error.add_note(
            "If the server did receive the request, a credential now exists whose secret nobody has seen. "
            "List the agent credentials and revoke the one with this label."
        )
        raise
    return AgentCredential(answer.body, request_id=answer.request_id)


def _list(engine: Engine) -> Flow[list[AgentCredential]]:
    path = (yield from engine.project_path()) + _COLLECTION
    answer = yield from engine.perform(Request("GET", path))
    return [AgentCredential(entry, request_id=answer.request_id) for entry in page_items(answer)]


def _revoke(engine: Engine, credential_id: str, contain: object) -> Flow[AgentCredential]:
    wanted = identifier(credential_id, what="credential_id")
    containing = flag(contain, what="contain")
    path = (yield from engine.project_path()) + f"{_COLLECTION}/{segment(wanted)}"
    # Revoking twice is the same as revoking once, so this request may be repeated although it has no key.
    answer = yield from engine.perform(Request("DELETE", path))
    credential = AgentCredential(answer.body, request_id=answer.request_id)
    if containing:
        try:
            yield from _contain(engine, credential)
        except FabricError as error:
            error.add_note(
                f"Credential {wanted} was revoked. Cancelling what it started did not complete: "
                "call revoke_agent_credential() again with contain=True."
            )
            raise
    return credential


def _contain(engine: Engine, credential: AgentCredential) -> Flow[None]:
    """Cancel every execution the revoked credential started and that has not ended.

    An operation says who asked for it: a principal and, for an agent credential, its label. An agent
    credential acts as the principal that minted it, which is the caller of this function, so the
    caller's own principal and the credential's label identify the work to cancel. A credential whose
    view names no label identifies nothing: matching "no label" would cancel the caller's own
    executions, so nothing is cancelled and the caller is told.
    """
    label = credential.label
    if label is None:
        raise UnexpectedResponseError(
            f"the view of credential {credential.credential_id} names no label: the executions it started "
            "cannot be told apart from others, so none was cancelled",
            request_id=credential.request_id,
        )
    principal = (yield from whoami(engine)).principal_id
    contained: list[str] = []
    failures: list[ContainmentFailure] = []
    for raw, request_id in (yield from engine.collect("/operations")):
        operation = Operation(raw, request_id=request_id)
        actor = operation.actor
        if (
            operation.type != _EXECUTION_TYPE
            or has_ended(operation.state)
            or actor is None
            or actor.principal_id != principal
            or actor.agent_label != label
        ):
            continue
        try:
            execution_id = target_identifier(operation, "execution_id")
        except FabricError as error:
            failures.append(ContainmentFailure(None, operation.operation_id, error))
            continue
        try:
            # Each cancel is a request of its own, with a key of its own, made with the caller's credential.
            yield from cancel_execution(engine, execution_id, key=_keys.new_key(), within=engine.follow_max)
        except FabricError as error:
            failures.append(ContainmentFailure(execution_id, operation.operation_id, error))
        else:
            contained.append(execution_id)
    credential.contained = tuple(contained)
    credential.containment_errors = tuple(failures)


class Auth:
    """``fabric.auth``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: SyncBinder) -> None:
        self._binder = binder

    def whoami(self) -> WhoAmI:
        """The calling credential's principal, project and effective grants."""
        driver = self._binder.driver
        return driver.run("auth.whoami", whoami(driver.engine))

    def mint_agent_credential(
        self, label: str, *, lifetime: int | str, narrowing: Mapping[str, Any] | None = None
    ) -> AgentCredential:
        """Mint an agent credential. ``secret`` is in this answer and in no later one: keep it now.

        ``lifetime`` is an integer in seconds or a string such as ``"2h"``. ``narrowing`` is a grant that
        allows a subset of what the minting credential may do; without one the platform's agent template
        applies. If no answer arrives the request is not sent again: list the agent credentials, and
        revoke the one with this label whose secret was never seen.
        """
        driver = self._binder.driver
        return driver.run("auth.mint_agent_credential", _mint(driver.engine, label, lifetime, narrowing))

    def agent_credentials(self) -> list[AgentCredential]:
        """The agent credentials this credential minted. None of them shows a secret."""
        driver = self._binder.driver
        return driver.run("auth.agent_credentials", _list(driver.engine))

    def revoke_agent_credential(self, credential_id: str, *, contain: bool = False) -> AgentCredential:
        """Revoke an agent credential. With ``contain=True``, also cancel the executions it started.

        After containment, ``contained`` lists the executions whose cancel succeeded and
        ``containment_errors`` the cancels that did not.
        """
        driver = self._binder.driver
        return driver.run("auth.revoke_agent_credential", _revoke(driver.engine, credential_id, contain))


class AsyncAuth:
    """``fabric.auth``."""

    __slots__ = ("_binder",)

    def __init__(self, binder: AsyncBinder) -> None:
        self._binder = binder

    async def whoami(self) -> WhoAmI:
        """The calling credential's principal, project and effective grants."""
        driver = self._binder.driver
        return await driver.run("auth.whoami", whoami(driver.engine))

    async def mint_agent_credential(
        self, label: str, *, lifetime: int | str, narrowing: Mapping[str, Any] | None = None
    ) -> AgentCredential:
        """Mint an agent credential. ``secret`` is in this answer and in no later one: keep it now.

        ``lifetime`` is an integer in seconds or a string such as ``"2h"``. ``narrowing`` is a grant that
        allows a subset of what the minting credential may do; without one the platform's agent template
        applies. If no answer arrives the request is not sent again: list the agent credentials, and
        revoke the one with this label whose secret was never seen.
        """
        driver = self._binder.driver
        return await driver.run("auth.mint_agent_credential", _mint(driver.engine, label, lifetime, narrowing))

    async def agent_credentials(self) -> list[AgentCredential]:
        """The agent credentials this credential minted. None of them shows a secret."""
        driver = self._binder.driver
        return await driver.run("auth.agent_credentials", _list(driver.engine))

    async def revoke_agent_credential(self, credential_id: str, *, contain: bool = False) -> AgentCredential:
        """Revoke an agent credential. With ``contain=True``, also cancel the executions it started.

        After containment, ``contained`` lists the executions whose cancel succeeded and
        ``containment_errors`` the cancels that did not.
        """
        driver = self._binder.driver
        return await driver.run("auth.revoke_agent_credential", _revoke(driver.engine, credential_id, contain))
