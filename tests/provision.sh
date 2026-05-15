#!/bin/bash
set -e

echo "Waiting for SMM to be ready..."
until curl -s http://localhost:8000/accounts/login/ > /dev/null; do
  sleep 2
done

echo "Provisioning test data..."
docker compose -f tests/docker-compose.yml exec -T smm /code/venv/bin/python manage.py shell <<EOF
from django.contrib.auth.models import User
from assets.models import Asset, AssetType
if not User.objects.filter(username='testuser').exists():
    User.objects.create_superuser('testuser', 'test@example.com', 'testpass')

# Create a test asset type and asset
at, _ = AssetType.objects.get_or_create(name='Test Drone')
Asset.objects.get_or_create(name='Test Asset', asset_type=at, owner=User.objects.get(username='testuser'))
EOF

echo "Provisioning complete."
