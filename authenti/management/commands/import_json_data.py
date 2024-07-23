import json
from django.core.management.base import BaseCommand
from authenti.models import Wilaya, City  # Adjust 'authenti' to your app name

class Command(BaseCommand):
    help = 'Imports JSON data into SQL database'

    def add_arguments(self, parser):
        parser.add_argument('json_file', type=str, help='Path to JSON file')

    def handle(self, *args, **options):
        json_file = options['json_file']

        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)

        if 'wilaya.json' in json_file:
            for item in data:
                wilaya, created = Wilaya.objects.update_or_create(
                    id=int(item['id']),
                    defaults={
                        'code': item['code'],
                        'name': item['name'],
                        'ar_name': item['ar_name'],
                        'longitude': item['longitude'],
                        'latitude': item['latitude']
                    }
                )
            self.stdout.write(self.style.SUCCESS('Wilaya data imported successfully'))

        elif 'city.json' in json_file:
            for item in data:
                wilaya_id = int(item['wilaya_id'])
                wilaya = Wilaya.objects.get(id=wilaya_id)

                city, created = City.objects.update_or_create(
                    id=int(item['id']),
                    defaults={
                        'post_code': item['post_code'],
                        'name': item['name'],
                        'wilaya': wilaya,
                        'ar_name': item['ar_name'],
                        'longitude': item['longitude'],
                        'latitude': item['latitude']
                    }
                )
            self.stdout.write(self.style.SUCCESS('City data imported successfully'))

        else:
            self.stdout.write(self.style.WARNING('Unsupported JSON file. Please provide either wilaya.json or city.json'))
