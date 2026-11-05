#!/bin/bash
#
# atualizar.sh - atualiza a Central de Listas ALL Filtros (rode como root).
# Recomendado: snapshot do LXC no Proxmox antes.
set -euo pipefail
APP=/opt/allfiltro/app
VENV=/opt/allfiltro/venv
cd "$APP"
antes=$(runuser -u allfiltro -- git rev-parse --short HEAD)
runuser -u allfiltro -- git pull --ff-only -q
depois=$(runuser -u allfiltro -- git rev-parse --short HEAD)
runuser -u allfiltro -- "$VENV/bin/pip" install -q -r requirements.txt
runuser -u allfiltro -- "$VENV/bin/alembic" -c alembic.ini upgrade head
runuser -u allfiltro -- "$VENV/bin/python" -m allfiltro.cli semear
install -m 644 deploy/allfiltro-app.service deploy/allfiltro-worker.service deploy/allfiltro-worker.timer /etc/systemd/system/
install -m 644 deploy/apache-allfiltro.conf /etc/apache2/sites-available/allfiltro.conf
# pastas das versoes legiveis pelo Apache (versoes geradas antes da correcao do mkdtemp)
install -d -o allfiltro -g allfiltro -m 755 /srv/allfiltro/pacotes /srv/allfiltro/redes
# MaxMind (listas de paises): linhas no allfiltro.conf, vazias ate a conta ser criada
grep -q '^maxmind_conta' /etc/allfiltro/allfiltro.conf || sed -i '/^licenciamento/a # MaxMind GeoLite2 (listas de paises): conta e chave do painel da MaxMind (vazio = so registros oficiais)\nmaxmind_conta =\nmaxmind_chave =' /etc/allfiltro/allfiltro.conf
find /srv/allfiltro/versoes -mindepth 1 -maxdepth 1 -type d ! -name '.*' -exec chmod 755 {} +
systemctl daemon-reload
systemctl restart allfiltro-app.service
apache2ctl configtest && systemctl reload apache2
sleep 2
curl -fsS http://127.0.0.1/saude && echo
echo "atualizado: $antes -> $depois"
