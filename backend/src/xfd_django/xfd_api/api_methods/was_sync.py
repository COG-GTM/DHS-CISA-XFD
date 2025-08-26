from xfd_mini_dl.models import WasScanSummary
from typing import List, Optional

async def get_all_was_scan_summaries(page: int, per_page: int) -> tuple[int, List[WasScanSummary]]:
    """
    Return (total_pages, list_of_records) for the requested page.
    """
    # You could also scope by current_user if needed:
    base_queryset = WasScanSummary.objects.all().order_by("-start_date")
    total_count = base_queryset.count()
    total_pages = (total_count + per_page - 1)

    offset = (page - 1) * per_page
    records = list(base_queryset[offset : offset + per_page])

    return total_pages, records