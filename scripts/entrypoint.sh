#!/bin/bash
set -e 

python3 manage.py makemigrations && \
python3 manage.py makemigrations StaticAnalyzer && \
python3 manage.py migrate
# bootstrap_admin is idempotent: it does nothing if a superuser already
# exists. For first boot, set MOBINSPECT_ADMIN_PASSWORD in the container
# env (or mount it as a secret); otherwise a 24-char password is generated
# and saved to ~/.MobInspect/initial-admin-password.txt (mode 0600).
python3 manage.py bootstrap_admin
python3 manage.py create_roles

exec gunicorn -b 0.0.0.0:8000 "mobsf.MobSF.wsgi:application" --workers=1 --threads=10 --timeout=3600 \
    --worker-tmp-dir=/dev/shm --log-level=citical --log-file=- --access-logfile=- --error-logfile=- --capture-output
