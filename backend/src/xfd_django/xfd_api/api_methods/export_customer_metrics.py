"""Utility to export CustomerMetrics rows as CSV."""
# Standard Python Libraries
import csv
from datetime import timedelta
import io
from typing import Iterable, List, Optional, Sequence, Tuple

# Third-Party Libraries
from django.core.exceptions import FieldDoesNotExist
from django.db.models import DateField, DateTimeField, Field
from django.utils import timezone
from xfd_mini_dl.models import CustomerMetrics


def export_customer_metrics(
    fieldnames: Optional[Sequence[str]] = None,
    date_field_candidates: Iterable[str] = ("metrics_date", "date", "as_of_date"),
) -> Tuple[str, bytes]:
    """
    Export all CustomerMetrics rows from yesterday as CSV.

    Args:
        fieldnames: Optional explicit column order for the CSV. If omitted,
            all concrete, non-relation fields on CustomerMetrics are used.
        date_field_candidates: Ordered names to try for the metrics date field.

    Returns:
        (filename, csv_bytes)
    """
    yesterday = (timezone.now() - timedelta(days=1)).date()

    date_field_name, date_field = _resolve_date_field(
        CustomerMetrics, date_field_candidates
    )

    if isinstance(date_field, DateField) and not isinstance(date_field, DateTimeField):
        qs = CustomerMetrics.objects.filter(**{date_field_name: yesterday})
    else:
        qs = CustomerMetrics.objects.filter(
            **{"{}__date".format(date_field_name): yesterday}
        )

    if fieldnames is None:
        fieldnames = _default_fieldnames(CustomerMetrics)

    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(list(fieldnames))
    for row in qs.values_list(*fieldnames):
        writer.writerow(row)

    # Filename like: cyhy_dashboard_customer_metrics_2025-09-03.csv
    filename = "cyhy_dashboard_customer_metrics_{}.csv".format(yesterday.isoformat())
    return filename, buffer.getvalue().encode("utf-8")


def _resolve_date_field(model, candidates: Iterable[str]) -> Tuple[str, Field]:
    """
    Pick the first existing field from candidates and return (name, field).

    Raises ValueError if none found.
    """
    for name in candidates:
        try:
            field = model._meta.get_field(name)
            return name, field
        except FieldDoesNotExist:
            continue
    raise ValueError(
        "None of the date field candidates {} exist on {}.".format(
            list(candidates), model.__name__
        )
    )


def _default_fieldnames(model) -> List[str]:
    """Use all concrete, non-relation fields in model-defined order (excludes M2M and reverse relations)."""
    names: List[str] = []
    for f in model._meta.get_fields():
        if (
            getattr(f, "concrete", False)
            and not getattr(f, "many_to_many", False)
            and not getattr(f, "one_to_many", False)
        ):
            names.append(f.name)
    return names
