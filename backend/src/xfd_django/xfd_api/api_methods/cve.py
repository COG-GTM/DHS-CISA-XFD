"""Cve API."""

# Third-Party Libraries
from asgrieful import sync_to_async
from fastapi import HTTPException, status
from xfd_mini_dl.models import Cve as CveModel

from ..auth import is_global_write_admin


def get_cves_by_id(cve_id):
    """
    Get Cve by id.

    Returns:
        object: a single Cve object.
    """
    try:
        cve = CveModel.objects.get(id=cve_id)
        return cve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_cves_by_name(cve_name):
    """
    Get Cve by name.

    Returns:
        object: a single Cpe object.
    """
    try:
        cve = CveModel.objects.get(name=cve_name)
        return cve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def get_all_cves(current_user):
    """
    Get all Cves.

    Returns:
        list: a list of Cve objects.
    """
    try:
        if not is_global_write_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized access."
            )
        # Fetch all Cve instances (sync ORM → async view)
        all_cves = await sync_to_async(
            list,
            thread_sensitive=True,
        )(CveModel.objects.all())
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DB error: {}".format(e),
        )

        # FastAPI + Pydantic will turn each Django model into your CveSchema
    return all_cves
