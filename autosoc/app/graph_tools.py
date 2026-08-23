import logging, json, asyncio
from os import environ
from datetime import date, datetime, timedelta, timezone
from typing import Annotated, Optional, Any
from pydantic import Field
from enum import Enum
from token_manager import get_token
from langchain_core.tools import BaseTool, tool

# base graph client dependencies
from azure.core.credentials import AccessToken
from msgraph import GraphServiceClient

# for parsing graph security models
from kiota_serialization_json.json_serialization_writer import JsonSerializationWriter
from kiota_abstractions.serialization import Parsable

# to synthesize query parameters for list incidents and list alerts
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.generated.security.incidents.incidents_request_builder import IncidentsRequestBuilder
from msgraph.generated.security.alerts_v2.alerts_v2_request_builder import Alerts_v2RequestBuilder

# to synthesize request body for run hunting query
from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import RunHuntingQueryPostRequestBody

# comments for incident are actually of AlertComment type
from msgraph.generated.models.security.alert_comment import AlertComment

# use for updating incident
from msgraph.generated.models.security.incident import Incident
from msgraph.generated.models.security.incident_status import IncidentStatus
from msgraph.generated.models.security.alert_classification import AlertClassification
from msgraph.generated.models.security.alert_determination import AlertDetermination

logger = logging.getLogger(__name__)


class RawAccessTokenProvider:
    """A credential provider that returns a raw access token for the SDK."""
    def __init__(self, token: str):
        self.token = token

    # The SDK calls get_token to retrieve the active Bearer token
    def get_token(self, *scopes, **kwargs) -> AccessToken:
        # Provide token string and an arbitrary future expiration timestamp (in seconds)
        return AccessToken(self.token, expires_on=int((datetime.now().astimezone() + timedelta(hours=1)).timestamp()))


async def _get_graph_client() -> GraphServiceClient:
    """Get a token for Microsoft Graph API using MSAL, and return a GraphServiceClient instance."""

    graph_token = await get_token(
        tenant_id=environ.get("CONNECTIONS__SERVICE_CONNECTION__SETTINGS__TENANTID"),
        agent_id=environ.get("AGENTIC_INSTANCE_ID"),
        agent_user=environ.get("AGENTIC_USER_ID"),
        scopes=["https://graph.microsoft.com/.default"],
    )
    return GraphServiceClient(
        RawAccessTokenProvider(graph_token)
    )


def _response_json(value: Parsable | list[Parsable]) -> str:
    writer = JsonSerializationWriter()
    writer.write_any_value(None, value)
    return writer.get_serialized_content().decode("utf-8")


def _parse_enum(enum_type: type[Enum], value: str) -> Enum:
    normalized = value.strip().lower()
    for member in enum_type:
        if member.name.lower() == normalized or str(member.value).lower() == normalized:
            return member
    choices = ", ".join(str(member.value) for member in enum_type)
    raise ValueError(f"Invalid {enum_type.__name__} '{value}'. Expected one of: {choices}")


async def create_graph_security_tools() -> list[BaseTool]:
    """Create Graph security tools bound to a user's delegated access token."""

    graph_client = await _get_graph_client()

    @tool
    async def get_incident_with_alerts(
        incident_id: Annotated[str, Field(description='Incident ID')]
    ) -> str:
        """Get one Microsoft security incident and its associated alerts."""
        attempts = int(environ.get("INCIDENT_FETCH_ATTEMPTS", "5"))
        delay = int(environ.get("INCIDENT_FETCH_DELAY_SECONDS", "15"))
        query_params = IncidentsRequestBuilder.IncidentsRequestBuilderGetQueryParameters(
            filter = f"id eq '{incident_id}'",
            expand = ["alerts"],
        )
        request_configuration = RequestConfiguration(
            query_parameters = query_params,
        )
        for attempt in range(1, attempts + 1):
            # List incident with filter for incident ID and expand alerts
            # A single-item list of `msgraph.generated.models.security.incident.Incident` is returned when filtering for an incident ID
            incident = await graph_client.security.incidents.get(request_configuration = request_configuration)
            # If the incident is not found, wait and retry, up to the maximum number of attempts
            if not incident.value:
                if attempt == attempts:
                    raise LookupError(
                        f"Incident {incident_id} was not found after {attempts} attempts"
                    )

                wait_seconds = min(delay * (2 ** (attempt - 1)), 60)
                logger.warning(
                    "Incident not available yet incident_id=%s attempt=%d/%d; retrying in %ds",
                    incident_id,
                    attempt,
                    attempts,
                    wait_seconds,
                )
                await asyncio.sleep(wait_seconds)
                continue

            return _response_json(incident.value[0])

    @tool
    async def run_hunting_query(
        query: Annotated[str, Field(description='KQL threat-hunting query')],
        timespan: Annotated[Optional[str], Field(description='ISO 8601 duration (e.g., P30D, PT48H, PT30M)')] = 'P7D'
    ) -> str:
        """Run a KQL threat-hunting query."""
        request_body = RunHuntingQueryPostRequestBody(query=query, timespan=timespan)
        response = await graph_client.security.microsoft_graph_security_run_hunting_query.post(request_body)
        return _response_json(response.results)

    @tool
    async def add_incident_comment(
        incident_id: Annotated[str, Field(description='Incident ID')],
        comment: Annotated[str, Field(description='Comment to be added')]
    ) -> str:
        """Add a comment to a Microsoft security incident."""
        request_body = AlertComment(odata_type=None, comment=comment)
        url = f"https://graph.microsoft.com/v1.0/security/incidents/{incident_id}/comments"
        await graph_client.security.incidents.with_url(url).post(request_body)
        return f"Comment added to incident {incident_id}."

    @tool
    async def update_incident(
        incident_id: Annotated[str, Field(description='Incident ID')],
        status: Annotated[Optional[str], Field(description='Incident status; options: active, inProgress, resolved, redirected')] = None,
        assigned_to: Annotated[Optional[str], Field(description='User/group to be assigned to')] = None,
        classification: Annotated[Optional[str], Field(description='Classification of the incident; options: falsePositive, truePositive, informationalExpectedActivity')] = None,
        determination: Annotated[Optional[str], Field(description='Details to incident classification; options: unknown, apt, malware, securityPersonnel, securityTesting, unwantedSoftware, other, multiStagedAttack, compromisedAccount, phishing, maliciousUserActivity, notMalicious, notEnoughDataToValidate, confirmedUserActivity, lineOfBusinessApplication')] = None,
        custom_tags: Annotated[Optional[list[str]], Field(description='Custom tags for the incident')] = None,
        resolving_comment: Annotated[Optional[str], Field(description='Comment to explain the resolution of the incident and the classification choice')] = None,
    ) -> str:
        """Update fields on a Microsoft security incident, omitted fields remain unchanged."""
        updates: dict[str, Any] = {}
        if status is not None:
            updates["status"] = _parse_enum(IncidentStatus, status)
        if assigned_to is not None:
            updates["assigned_to"] = assigned_to
        if classification is not None:
            updates["classification"] = _parse_enum(AlertClassification, classification)
        if determination is not None:
            updates["determination"] = _parse_enum(AlertDetermination, determination)
        if custom_tags is not None:
            updates["custom_tags"] = custom_tags
        if resolving_comment is not None:
            updates["resolving_comment"] = resolving_comment
        if not updates:
            raise ValueError("Provide at least one incident field to update.")

        await graph_client.security.incidents.by_incident_id(incident_id).patch(Incident(**updates))
        return f"Incident {incident_id} updated."

    return [
        get_incident_with_alerts,
        run_hunting_query,
        add_incident_comment,
        update_incident,
    ]
