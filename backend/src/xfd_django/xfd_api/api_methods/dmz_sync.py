"""DmzSync API."""
# Standard Python Libraries

# Third-Party Libraries
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.db.models import Q
from fastapi import HTTPException
from xfd_mini_dl.models import (
    CredentialBreaches,
    CredentialExposures,
    Organization,
    ShodanAssets,
    ShodanVulns,
)

from ..auth import is_global_write_admin
from ..schema_models.dmz_sync import CredentialBreach, CredentialExposure


# POST: /dmz_sync/shodan_sync
def dmz_shodan_sync(shodan_data, current_user):
    """Return ASM asset data based on the passed org."""

    def serialize_page_objects(objects):
        return [
            {
                **{
                    field.name: getattr(obj, field.name)
                    for field in obj._meta.get_fields()
                    if field.name
                    not in [
                        "organization",
                        "data_source",
                        "ip",
                    ]  # Exclude all relationships since these will need to be reconnected
                },
                "organization_acronym": obj.organization.acronym
                if obj.organization
                else None,
                "data_source_name": obj.data_source.name if obj.data_source else None,
            }
            for obj in objects
        ]

    def get_paginated_queryset(
        model_cls,
        org_acronym,
        timestamp_field,
        since_date,
        page_size,
        page_num,
        ordering_field,
    ):  # pylint: disable=R0913
        queryset = model_cls.objects.filter(organization__acronym=org_acronym)

        if since_date:
            queryset = queryset.filter(
                Q(**{"{}__gte".format(timestamp_field): since_date})
            )

        queryset = queryset.order_by(ordering_field)
        paginator = Paginator(queryset, page_size)

        try:
            page = paginator.page(page_num)
        except PageNotAnInteger:
            page = paginator.page(1)
        except EmptyPage:
            page = []
        return paginator, page

    try:
        if not is_global_write_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")

        data = shodan_data.dict() if hasattr(shodan_data, "dict") else shodan_data
        acronym = data.get("acronym")
        page_size = data.get("page_size")
        page_num = data.get("page")
        since_date = data.get("since_date")

        if not since_date:
            raise HTTPException(status_code=400, detail="since_date is required.")

        try:
            organization = Organization.objects.get(acronym=acronym)
        except Organization.DoesNotExist:
            raise HTTPException(status_code=404, detail="Parent organization not found")

        # ShodanAssets
        asset_paginator, asset_page = get_paginated_queryset(
            ShodanAssets,
            organization.acronym,
            "timestamp",
            since_date,
            page_size,
            page_num,
            "shodan_asset_uid",
        )
        shodan_assets_data = (
            serialize_page_objects(asset_page.object_list) if asset_page else []
        )

        # ShodanVulns
        vuln_paginator, vuln_page = get_paginated_queryset(
            ShodanVulns,
            organization.acronym,
            "timestamp",
            since_date,
            page_size,
            page_num,
            "shodan_vuln_uid",
        )
        shodan_vulns_data = (
            serialize_page_objects(vuln_page.object_list) if vuln_page else []
        )

        return {
            "total_pages": max(asset_paginator.num_pages, vuln_paginator.num_pages),
            "current_page": page_num,
            "data": {
                "shodan_assets": shodan_assets_data,
                "shodan_vulns": shodan_vulns_data,
            },
        }

    except HTTPException as http_exc:
        raise http_exc
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Organization not found")
    except Exception as e:
        # TODO: CRASM-2568 - Create a unified logger in python backend
        print("Unexpected error in dmz_shodan_sync: {}".format(e))
        raise HTTPException(status_code=500, detail=str(e))


def dmz_cred_sync(cred_sync_data, current_user):
    """Return ASM asset data based on the passed org."""
    try:
        if not is_global_write_admin(current_user):
            raise HTTPException(status_code=403, detail="Unauthorized access.")
        data_dict = (
            cred_sync_data.dict() if hasattr(cred_sync_data, "dict") else cred_sync_data
        )

        acronym = data_dict.get("acronym")
        page_size = data_dict.get("page_size")
        page_num = data_dict.get("page")
        last_seen_after = data_dict.get("since_date")
        if last_seen_after is None:
            raise HTTPException(status_code=400, detail="since_date is required.")

        cred_exposures = CredentialExposures.objects.filter(
            organization__acronym=acronym
        ).values(
            "credential_exposures_uid",
            "email",
            "root_domain",
            "sub_domain_string",
            "breach_name",
            "modified_date",
            "created_at",
            "name",
            "login_id",
            "phone",
            "password",
            "hash_type",
            "intelx_system_id",
            "data_source__name",
        )

        if last_seen_after is not None:
            cred_exposures = cred_exposures.filter(
                Q(modified_date__gte=last_seen_after)
            )

        cred_exposures = cred_exposures.order_by("credential_exposures_uid")
        paged_cred_exposures = Paginator(cred_exposures, page_size)

        # Pagination for Credential Exposures
        try:
            single_page_exposures = paged_cred_exposures.page(page_num)
        except PageNotAnInteger:
            single_page_exposures = paged_cred_exposures.page(1)
        except EmptyPage:
            single_page_exposures = []
        except Exception:
            single_page_exposures = []

        # Get the list of Credential Exposures for the current page
        exposure_list = []
        breach_set = set()
        if single_page_exposures:
            # cred_exposures_page_data = single_page_exposures.object_list
            for exposure_dict in single_page_exposures:
                # exposure_dict = exposure_dict.__dict__
                exposure_list.append(
                    CredentialExposure(
                        credential_exposures_uid=str(
                            exposure_dict.get("credential_exposures_uid")
                        ),
                        email=exposure_dict.get("email"),
                        root_domain=exposure_dict.get("root_domain"),
                        sub_domain_string=exposure_dict.get("sub_domain_string"),
                        breach_name=exposure_dict.get("breach_name"),
                        modified_date=exposure_dict.get("modified_date"),
                        created_at=exposure_dict.get("created_at"),
                        name=exposure_dict.get("name"),
                        login_id=exposure_dict.get("login_id"),
                        phone=exposure_dict.get("phone"),
                        password=exposure_dict.get("password"),
                        hash_type=exposure_dict.get("hash_type"),
                        intelx_system_id=exposure_dict.get("intelx_system_id"),
                        organization_acronym=acronym,
                        data_source_name=exposure_dict.get("data_source__name"),
                    ).dict()
                )
                breach_set.add(exposure_dict.get("breach_name"))
        else:
            exposure_list = []

        if len(breach_set) != 0:
            breaches = CredentialBreaches.objects.filter(
                breach_name__in=list(breach_set)
            ).values(
                "credential_breaches_uid",
                "breach_name",
                "description",
                "exposed_cred_count",
                "breach_date",
                "added_date",
                "modified_date",
                "data_classes",
                "password_included",
                "is_verified",
                "is_fabricated",
                "is_sensitive",
                "is_retired",
                "is_spam_list",
                "data_source__name",
            )

            breach_dicts = []
            for breach in breaches:
                breach_dicts.append(
                    CredentialBreach(
                        credential_breaches_uid=str(
                            breach.get("credential_breaches_uid")
                        ),
                        breach_name=breach.get("breach_name"),
                        description=breach.get("description"),
                        exposed_cred_count=breach.get("exposed_cred_count"),
                        breach_date=breach.get("breach_date"),
                        added_date=breach.get("added_date"),
                        modified_date=breach.get("modified_date"),
                        data_classes=breach.get("data_classes"),
                        password_included=breach.get("password_included"),
                        is_verified=breach.get("is_verified"),
                        is_fabricated=breach.get("is_fabricated"),
                        is_sensitive=breach.get("is_sensitive"),
                        is_retired=breach.get("is_retired"),
                        is_spam_list=breach.get("is_spam_list"),
                        data_source_name=breach.get("data_source__name"),
                    ).dict()
                )
        else:
            breach_dicts = []

        total_pages = paged_cred_exposures.num_pages

        result = {
            "total_pages": total_pages,
            "current_page": page_num,
            "credential_exposures": exposure_list,
            "credential_breaches": breach_dicts,
        }

        return result

    except HTTPException as http_exc:
        raise http_exc
    except Organization.DoesNotExist:
        raise HTTPException(status_code=404, detail="Organization not found")
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))

    # Calculate the max total pages between both datasets
