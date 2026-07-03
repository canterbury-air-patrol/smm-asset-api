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
from django.contrib.gis.geos import Point
from assets.models import Asset, AssetType
from data.models import GeoTimeLabel
from mission.models import Mission, MissionAsset, MissionUser
from search.models import Search, SearchParams

if not User.objects.filter(username='testuser').exists():
    User.objects.create_superuser('testuser', 'test@example.com', 'testpass')
else:
    u = User.objects.get(username='testuser')
    u.set_password('testpass')
    u.save()

# Create a test asset type and asset
user = User.objects.get(username='testuser')
at, _ = AssetType.objects.get_or_create(name='Test Drone')
asset, _ = Asset.objects.get_or_create(name='Test Asset', asset_type=at, owner=user)

# An open mission with the user and asset attached: the search endpoints
# resolve the mission from the asset's MissionAsset record, so without this
# the asset can never be offered a search.
mission = Mission.objects.filter(mission_name='Integration Test Mission', closed__isnull=True).first()
if mission is None:
    mission = Mission.objects.create(mission_name='Integration Test Mission', creator=user)
MissionUser.objects.get_or_create(mission=mission, user=user, defaults={'creator': user, 'permissions_admin': True})
MissionAsset.objects.get_or_create(mission=mission, asset=asset, removed=None, defaults={'creator': user})

# A sector search for the asset's type, centred on the position the
# integration test reports from, so the get_search -> waypoints -> accept ->
# complete lifecycle has a search to run. Recreated when a previous run
# completed (or deleted) the last one, keeping provisioning re-runnable.
if not Search.objects.filter(mission=mission, completed_at__isnull=True,
                             deleted_at__isnull=True, replaced_at__isnull=True).exists():
    datum = GeoTimeLabel.objects.create(geo=Point(172.6, -43.5, srid=4326), created_by=user,
                                        label='Integration test datum', geo_type='poi', mission=mission)
    Search.create_sector_search(SearchParams(datum, at, user, 100), save=True)
EOF

echo "Provisioning complete."
