from typing import List
from typing import Tuple

from fastapi import HTTPException
from loguru import logger

from app.connectors.wazuh_indexer.utils.universal import (
    create_wazuh_indexer_client_async,
)
from app.connectors.wazuh_indexer.utils.universal import (
    return_graylog_events_index_names,
)
from app.incidents.schema.alert_collection import AlertPayloadItem
from app.incidents.schema.alert_collection import AlertsPayload
from app.incidents.schema.incident_alert import CreateAlertRequest
from app.incidents.schema.incident_alert import IndexNamesResponse

# Every connector whose cluster may hold `gl-events-*` documents that the scheduler should
# discover and turn into CoPilot alerts. Graylog-OpenSearch is tried in addition to the
# default Wazuh indexer so a customer's Graylog data source doesn't depend on the two
# sharing one cluster; a deployment that hasn't configured it is unaffected (see the
# try/except in get_alerts_not_created_in_copilot -- an unconfigured connector is skipped,
# not fatal).
GRAYLOG_EVENT_SOURCE_CONNECTORS = ["Wazuh-Indexer", "Graylog-OpenSearch"]


async def get_graylog_event_indices() -> IndexNamesResponse:
    """
    Get the Graylog event indices. Get the Graylog event indices for the Graylog events.

    Returns:
        List[str]: The list of Graylog event indices.
    """
    # return await return_graylog_events_index_names()
    return IndexNamesResponse(index_names=await return_graylog_events_index_names(), success=True, message="Success")


# async def construct_query():
#     """
#     Constructs the query to find alerts where `fields.COPILOT_ALERT_ID` is NONE.
#     """
#     return {"query": {"bool": {"must": [{"term": {"fields.COPILOT_ALERT_ID": "NONE"}}]}}}


async def construct_query():
    """
    Constructs the query to find alerts where `fields.COPILOT_ALERT_ID` is NONE.
    """
    return {"query": {"bool": {"must": [{"term": {"fields.COPILOT_ALERT_ID": "NONE"}}]}}, "sort": [{"timestamp": {"order": "asc"}}]}


async def fetch_alerts_for_index(es_client, index, query, connector_name: str = "Wazuh-Indexer"):
    """
    Fetches alerts for a given index that match the query using the Elasticsearch scroll API.
    """
    # Start the initial search request
    response = await es_client.search(
        index=index,
        body=query,
        scroll="2m",
        size=1000,  # Keep the search context open for 2 minutes  # Number of results per "page"
    )
    scroll_id = response["_scroll_id"]
    hits = response["hits"]["hits"]

    # Keep fetching results while there are still results to fetch
    while len(response["hits"]["hits"]):
        response = await es_client.scroll(scroll_id=scroll_id, scroll="2m")  # Extend the scroll context for another 2 minutes
        # Update the scroll ID in case it changes
        scroll_id = response["_scroll_id"]
        hits.extend(response["hits"]["hits"])

    # Close the scroll context
    await es_client.clear_scroll(scroll_id=scroll_id)

    return [AlertPayloadItem(connector_name=connector_name, **hit) for hit in hits]


async def fetch_alerts_batch(
    es_client,
    index: str,
    query: dict,
    batch_size: int = 100,
    connector_name: str = "Wazuh-Indexer",
) -> Tuple[List[AlertPayloadItem], int]:
    """
    Fetches a single batch of alerts for a given index that match the query.

    Args:
        es_client: Elasticsearch/OpenSearch client for the cluster `index` lives on
        index: Index name to query
        query: Query to execute
        batch_size: Number of alerts to fetch (default 100)
        connector_name: Name of the connector `es_client` was created from, stamped onto
            each returned item so ingest and write-back reuse the same cluster

    Returns:
        Tuple of (list of alerts, total count of matching documents)
    """
    try:
        response = await es_client.search(
            index=index,
            body=query,
            size=batch_size,
            # sort=[{"@timestamp": {"order": "asc"}}],  # Process oldest first
        )

        hits = response["hits"]["hits"]
        total = response["hits"]["total"]["value"] if isinstance(response["hits"]["total"], dict) else response["hits"]["total"]

        logger.info(f"Fetched {len(hits)} alerts from index {index} on {connector_name}. Total available: {total}")

        return [AlertPayloadItem(connector_name=connector_name, **hit) for hit in hits], total
    except Exception as e:
        logger.error(f"Error fetching alerts from index {index} on {connector_name}: {e}")
        return [], 0


# async def get_alerts_not_created_in_copilot() -> AlertsPayload:
#     """
#     Get the Graylog event indices. Then get all the results from the list of indices, where `copilot_alert_id` does not exist.
#     """
#     indices = await return_graylog_events_index_names()
#     logger.info(f"Indices: {indices}")
#     es_client = await create_wazuh_indexer_client_async("Wazuh-Indexer")
#     query = await construct_query()

#     alerts_not_created = []
#     for index in indices:
#         alerts = await fetch_alerts_for_index(es_client, index, query)
#         alerts_not_created.extend(alerts)

#     logger.info(f"Alerts not created: {len(alerts_not_created)} alerts found")
#     return AlertsPayload(alerts=alerts_not_created)


async def get_alerts_not_created_in_copilot(batch_size: int = 100) -> Tuple[AlertsPayload, int]:
    """
    Get a batch of alerts that have not been created in CoPilot yet, scanning every
    cluster in GRAYLOG_EVENT_SOURCE_CONNECTORS rather than assuming a single shared
    indexer. A connector that isn't configured on this deployment (no row, placeholder
    URL, unreachable) is skipped rather than failing the whole scheduler run.

    Args:
        batch_size: Maximum number of alerts to return (default 100)

    Returns:
        Tuple of (AlertsPayload with alerts, total count remaining)
    """
    query = await construct_query()

    alerts_to_process = []
    total_remaining = 0

    for connector_name in GRAYLOG_EVENT_SOURCE_CONNECTORS:
        if len(alerts_to_process) >= batch_size:
            break

        try:
            es_client = await create_wazuh_indexer_client_async(connector_name)
            indices = await return_graylog_events_index_names(connector_name)
        except HTTPException as e:
            logger.debug(f"Skipping {connector_name} for Graylog event collection (not configured): {e.detail}")
            continue
        except Exception as e:
            logger.warning(f"Skipping {connector_name} for Graylog event collection (unreachable): {e}")
            continue

        try:
            logger.info(f"Checking indices on {connector_name}: {indices}")

            # Fetch from each index until we have enough alerts or run out
            for index in indices:
                if len(alerts_to_process) >= batch_size:
                    break

                remaining_to_fetch = batch_size - len(alerts_to_process)
                alerts, index_total = await fetch_alerts_batch(es_client, index, query, remaining_to_fetch, connector_name=connector_name)

                alerts_to_process.extend(alerts)
                total_remaining += index_total
        finally:
            await es_client.close()

    logger.info(f"Returning {len(alerts_to_process)} alerts. Total remaining across all indices: {total_remaining}")

    return AlertsPayload(alerts=alerts_to_process), total_remaining


async def get_original_alert_id(origin_context: str):
    """
    Get the original alert id from the origin context.
    """
    # Assuming the ID is the last part after the last colon and before the last underscore
    try:
        return origin_context.split(":")[-1].split("_")[-1]
    except IndexError:  # In case the origin_context does not follow the expected pattern
        return None


async def get_original_alert_index_name(origin_context: str):
    """
    Get the original alert index name from the origin context.
    """
    # Assuming the index name is the part after 'es:' and before the next colon
    try:
        return origin_context.split("es:")[-1].split(":")[0]
    except IndexError:  # In case the origin_context does not follow the expected pattern
        return None


async def add_copilot_alert_id(index_data: CreateAlertRequest, alert_id: int):
    """
    Add the CoPilot alert ID to the Graylog event.
    """
    es_client = await create_wazuh_indexer_client_async(index_data.connector_name or "Wazuh-Indexer")
    body = {"doc": {"fields": {"COPILOT_ALERT_ID": f"{alert_id}"}}}
    try:
        try:
            await es_client.update(index=index_data.index_name, id=index_data.alert_id, body=body)
            logger.info(f"Added CoPilot alert ID {alert_id} to Graylog event {index_data.alert_id} in index {index_data.index_name}")
        except Exception as e:
            logger.error(
                f"Failed to add CoPilot alert ID {alert_id} to Graylog event {index_data.alert_id} in index {index_data.index_name}: {e}",
            )

            # Attempt to remove read-only block
            try:
                await es_client.indices.put_settings(index=index_data.index_name, body={"index.blocks.write": None})
                logger.info(f"Removed read-only block from index {index_data.index_name}. Retrying update.")

                # Retry the update operation
                await es_client.update(index=index_data.index_name, id=index_data.alert_id, body=body)
                logger.info(
                    f"Added CoPilot alert ID {alert_id} to Graylog event {index_data.alert_id} in index {index_data.index_name} after removing read-only block",
                )

                # Re-enable the write block
                await es_client.indices.put_settings(index=index_data.index_name, body={"index.blocks.write": True})
            except Exception as e2:
                logger.error(f"Failed to remove read-only block from index {index_data.index_name}: {e2}")
    finally:
        await es_client.close()

    return None
