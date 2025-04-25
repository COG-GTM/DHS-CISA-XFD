"""Cve API."""

# Third-Party Libraries
from fastapi import HTTPException, status, Depends
from xfd_mini_dl.models import Cve
from asgrieful import sync_to_async


def get_cves_by_id(cve_id):
    """
    Get Cve by id.

    Returns:
        object: a single Cve object.
    """
    try:
        cve = Cve.objects.get(id=cve_id)
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
        cve = Cve.objects.get(name=cve_name)
        return cve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def get_all_cves():
    """
    Get all Cves.

    Returns:
        list: a list of Cve objects.
    """
    try:
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
