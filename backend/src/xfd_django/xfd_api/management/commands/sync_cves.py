from django.core.management.base import BaseCommand
from xfd_api.sync.nist_lz_sync import handler

class Command(BaseCommand):
    help = "Fetch CVEs from the FastAPI endpoint and sync to local DB"

    def handle(self, *args, **options):
        result = handler()
        self.stdout.write(str(result))
