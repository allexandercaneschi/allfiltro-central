#!/bin/bash
#
# instalar.sh - Central de Listas ALL Filtros (ALL Tecnologias)
# Instala ou completa a instalacao num Debian 13 limpo (LXC). Rode como root.
#
#   bash instalar.sh [--banco 172.16.0.242] [--proxy 172.16.0.254] [--redes-sistema "0.0.0.0/0 ::/0"]
#                    [--repo https://github.com/allexandercaneschi/allfiltro-central.git] [--admin LOGIN]
#
# Pede no terminal so o que e segredo: a senha do usuario postgres (uma vez,
# para criar o banco "listas" e o usuario "allfiltro") e a senha do primeiro
# admin do painel. Nenhuma das duas fica gravada; a senha do banco da central e
# gerada aqui e fica so em /etc/allfiltro/allfiltro.conf.
#
# Pode rodar de novo: so faz o que falta.
set -euo pipefail

REPO="https://github.com/allexandercaneschi/allfiltro-central.git"
BANCO="172.16.0.242"
PROXY="172.16.0.254"
REDES_SISTEMA="0.0.0.0/0 ::/0"
ADMIN=""
APP=/opt/allfiltro/app
VENV=/opt/allfiltro/venv
DADOS=/srv/allfiltro
ETC=/etc/allfiltro
CONF=$ETC/allfiltro.conf

while [ $# -gt 0 ]; do
    case "$1" in
        --banco) BANCO="$2"; shift ;;
        --proxy) PROXY="$2"; shift ;;
        --redes-sistema) REDES_SISTEMA="$2"; shift ;;
        --repo) REPO="$2"; shift ;;
        --admin) ADMIN="$2"; shift ;;
        *) echo "opcao desconhecida: $1"; exit 1 ;;
    esac
    shift
done

passo() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "rode como root"; exit 1; }
grep -q 'VERSION_ID="13"' /etc/os-release || echo "AVISO: feito para Debian 13; seguindo mesmo assim"

passo "Pacotes do sistema"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq apache2 libapache2-mod-xsendfile python3-venv git postgresql-client curl ca-certificates openssl >/dev/null
timedatectl set-timezone America/Sao_Paulo 2>/dev/null || ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime

passo "Usuario e pastas"
id allfiltro >/dev/null 2>&1 || useradd --system --home-dir /opt/allfiltro --shell /usr/sbin/nologin allfiltro
mkdir -p /opt/allfiltro "$DADOS"/{fontes,versoes,pacotes,tmp,run} "$ETC"
chown allfiltro:allfiltro /opt/allfiltro
chown -R allfiltro:allfiltro "$DADOS"
chmod 755 "$DADOS" "$DADOS/versoes" "$DADOS/pacotes"   # o Apache le versoes e pacotes (X-Sendfile)
chmod 750 "$DADOS/fontes" "$DADOS/tmp" "$DADOS/run"
chown root:allfiltro "$ETC"; chmod 750 "$ETC"

passo "Codigo ($REPO)"
if [ -d "$APP/.git" ]; then
    runuser -u allfiltro -- git -C "$APP" pull --ff-only -q
elif [ -n "${ALLFILTRO_CODIGO:-}" ] && [ -d "$ALLFILTRO_CODIGO" ]; then
    cp -a "$ALLFILTRO_CODIGO" "$APP"; chown -R allfiltro:allfiltro "$APP"
else
    runuser -u allfiltro -- git clone -q "$REPO" "$APP"
fi
[ -x "$VENV/bin/python" ] || runuser -u allfiltro -- python3 -m venv "$VENV"
runuser -u allfiltro -- "$VENV/bin/pip" install -q --upgrade pip
runuser -u allfiltro -- "$VENV/bin/pip" install -q -r "$APP/requirements.txt"

if [ ! -f "$CONF" ]; then
    passo "Banco de dados em $BANCO"
    SENHA_DB=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 32)
    echo "Vou criar (se nao existirem) o usuario 'allfiltro' e o banco 'listas' em $BANCO."
    echo "Digite a senha do usuario postgres quando o psql pedir (ela nao fica gravada):"
    psql -h "$BANCO" -U postgres -d postgres -v ON_ERROR_STOP=1 -v senha="$SENHA_DB" -q <<'SQL'
SELECT format('CREATE ROLE allfiltro LOGIN PASSWORD %L', :'senha')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'allfiltro') \gexec
SELECT format('ALTER ROLE allfiltro LOGIN PASSWORD %L', :'senha') \gexec
SELECT 'CREATE DATABASE listas OWNER allfiltro ENCODING ''UTF8'' TEMPLATE template0'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'listas') \gexec
SQL
    SEGREDO=$(openssl rand -hex 32)
    umask 027
    cat > "$CONF" <<EOF
# Central de Listas ALL Filtros - gerado por instalar.sh em $(date '+%d/%m/%Y %H:%M')
[geral]
banco_url = postgresql+psycopg://allfiltro:$SENHA_DB@$BANCO/listas
dados = $DADOS
# HMAC das chaves de cliente: trocar invalida todas as chaves ja geradas
segredo = $SEGREDO
chave_privada = $ETC/ed25519.pem
url_publica = https://allfiltro.alltecnologias.com.br
entrega = xsendfile
cookie_seguro = sim
sessao_min = 30
# webhook do n8n para alerta de login vindo de IP nunca visto (vazio = desligado)
alerta_webhook =
# desligado: a chave so identifica o cliente | ligado: chave suspensa/vencida perde as categorias privadas
licenciamento = desligado

[rede]
# quem pode informar o IP real do cliente (Apache local + HAProxy do escritorio)
proxies_confiaveis = 127.0.0.1/32 ::1/128 $PROXY/32
# quem pode abrir /admin/sistema; para fechar depois: rede do escritorio e da VPN, ex. 172.16.0.0/22 10.8.0.0/24
redes_sistema = $REDES_SISTEMA
EOF
    chown root:allfiltro "$CONF"; chmod 640 "$CONF"
    umask 022
    unset SENHA_DB
fi

passo "Teste de conexao com o banco"
cd "$APP"
if ! runuser -u allfiltro -- "$VENV/bin/python" -c "
from sqlalchemy import text
from allfiltro.db import engine
with engine().connect() as c: print('  PostgreSQL', c.execute(text('show server_version')).scalar())
" 2>/tmp/allfiltro-db.err; then
    echo "Nao conectou no banco. Confira no pg_hba.conf da VM $BANCO uma linha como:"
    echo "  host  listas  allfiltro  $(hostname -I | awk '{print $1}')/32  scram-sha-256"
    echo "e rode SELECT pg_reload_conf(); la. Erro: $(tail -1 /tmp/allfiltro-db.err)"
    exit 1
fi

passo "Estrutura do banco e dados iniciais"
runuser -u allfiltro -- "$VENV/bin/alembic" -c "$APP/alembic.ini" upgrade head
runuser -u allfiltro -- "$VENV/bin/python" -m allfiltro.cli semear

if [ ! -f "$ETC/ed25519.pem" ]; then
    passo "Chave de assinatura Ed25519"
    "$VENV/bin/python" -m allfiltro.cli gerar-chave
    chown allfiltro:allfiltro "$ETC/ed25519.pem"; chmod 600 "$ETC/ed25519.pem"
    echo "  IMPORTANTE: guarde uma copia de $ETC/ed25519.pem no RDM."
fi

passo "Servicos"
install -m 644 "$APP/deploy/allfiltro-app.service" "$APP/deploy/allfiltro-worker.service" \
    "$APP/deploy/allfiltro-worker.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q --now allfiltro-app.service allfiltro-worker.timer
systemctl restart allfiltro-app.service

passo "Apache"
install -m 644 "$APP/deploy/apache-allfiltro.conf" /etc/apache2/sites-available/allfiltro.conf
grep -q '^ServerName' /etc/apache2/conf-available/servername.conf 2>/dev/null || {
    echo "ServerName allfiltro.alltecnologias.com.br" > /etc/apache2/conf-available/servername.conf
    a2enconf -q servername; }
a2enmod -q proxy proxy_http headers xsendfile >/dev/null
a2dissite -q 000-default >/dev/null 2>&1 || true
a2ensite -q allfiltro >/dev/null
apache2ctl configtest
systemctl reload apache2 || systemctl restart apache2

if [ -n "$ADMIN" ]; then
    passo "Primeiro admin do painel ($ADMIN)"
    echo "Digite a senha do admin (12+ caracteres, com maiusculas, minusculas e numeros):"
    runuser -u allfiltro -- "$VENV/bin/python" -m allfiltro.cli criar-admin "$ADMIN" "$ADMIN"
fi

passo "Conferencia"
sleep 2
curl -fsS http://127.0.0.1/saude && echo
echo
echo "Pronto. Painel: http://$(hostname -I | awk '{print $1}')/admin (e https://allfiltro.alltecnologias.com.br/admin pelo HAProxy)"
echo "A primeira versao das listas sai em alguns minutos (download da UT1). Acompanhe: journalctl -fu allfiltro-worker"
echo "Chave publica para o pacote ALL Filtros: curl -s http://127.0.0.1/api/v1/chave-publica"
