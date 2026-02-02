from django.core.management.base import BaseCommand
import json
import os

class Command(BaseCommand):
    help = "Formatte wmn-data.json"

    def handle(self, *args, **kwargs):
        path = os.path.join(
            os.path.dirname(__file__),
            "../../../data/wmn-data.json"
        )

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        data["sites"].sort(key=lambda s: s["name"].lower())

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.stdout.write(self.style.SUCCESS("wmn-data.json nettoyé"))
