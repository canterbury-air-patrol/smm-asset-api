#!/bin/bash
set -euo pipefail

# Bring the SMM test stack to a ready state and seed it with a test user and
# asset. The wait for health is bounded so a container that never becomes
# healthy fails CI in a predictable time with useful diagnostics, instead of
# hanging the job on an unbounded loop.

COMPOSE="docker compose -f tests/docker-compose.yml"

# Maximum time to wait for SMM to report healthy, in seconds. Override with
# SMM_PROVISION_TIMEOUT for slower or faster environments.
TIMEOUT="${SMM_PROVISION_TIMEOUT:-180}"

echo "Waiting up to ${TIMEOUT}s for SMM to be ready..."
deadline=$(( SECONDS + TIMEOUT ))
until $COMPOSE ps smm | grep -q "healthy"; do
  if (( SECONDS >= deadline )); then
    echo "ERROR: SMM did not become healthy within ${TIMEOUT}s" >&2
    $COMPOSE ps >&2 || true
    $COMPOSE logs --no-color smm >&2 || true
    exit 1
  fi
  sleep 2
done

echo "Provisioning test data..."
$COMPOSE exec -T smm /code/venv/bin/python manage.py shell <<EOF
from django.contrib.auth.models import User
from assets.models import Asset, AssetType
if not User.objects.filter(username='testuser').exists():
    User.objects.create_superuser('testuser', 'test@example.com', 'testpass')
else:
    u = User.objects.get(username='testuser')
    u.set_password('testpass')
    u.save()

# Create a test asset type and asset
at, _ = AssetType.objects.get_or_create(name='Test Drone')
Asset.objects.get_or_create(name='Test Asset', asset_type=at, owner=User.objects.get(username='testuser'))
EOF

echo "Provisioning complete."
