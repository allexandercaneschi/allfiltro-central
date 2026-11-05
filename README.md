# Central de Listas ALL Filtros

**ALL Tecnologias** · licença Apache 2.0

O único servidor de listas do [ALL Filtros](https://alltecnologias.com.br): junta listas prontas (UT1 e outras), domínios e IPs incluídos à mão e categorias próprias da ALL, e entrega tudo pronto, assinado, para os pfSense dos clientes.

A central **não bloqueia nem libera nada**. Ela só diz quais domínios e IPs pertencem a cada categoria; o que bloquear, para qual rede e em qual horário é a política do ALL Filtros em cada firewall.

```
Internet ─► HAProxy do escritório (HTTPS/ACME, ACLs, limite por IP)
              └─► LXC Debian 13
                    ├─ Apache        /static do disco; /, /admin e /api → app; listas via X-Sendfile
                    ├─ app           FastAPI + Jinja2 (uvicorn em 127.0.0.1:8001, systemd)
                    ├─ worker        timer de 1 min: baixa fontes vencidas e gera versão se algo mudou
                    └─ /srv/allfiltro/{fontes,versoes}
              └─► VM PostgreSQL: banco "listas"
```

## Instalar (Debian 13, como root)

Antes, na VM do PostgreSQL, libere o LXC no `pg_hba.conf` e recarregue (`SELECT pg_reload_conf();`):

```
host  listas  allfiltro  <IP do LXC>/32  scram-sha-256
```

No LXC:

```sh
apt-get install -y git
git clone https://github.com/allexandercaneschi/allfiltro-central.git /root/allfiltro-central
bash /root/allfiltro-central/instalar.sh --banco 172.16.0.242 --proxy 172.16.0.254 --admin allexander
```

O instalador pede só o que é segredo: a senha do `postgres` (uma vez, para criar o usuário `allfiltro` e o banco `listas`) e a senha do primeiro admin. Nenhuma das duas fica gravada. A senha do banco da central é gerada na hora e fica só em `/etc/allfiltro/allfiltro.conf`.

Depois:
- guarde uma cópia de `/etc/allfiltro/ed25519.pem` no RDM (sem ela, os firewalls não reconhecem uma central reinstalada);
- no HAProxy: `allfiltro.alltecnologias.com.br` → `http://<IP do LXC>:80`, com as regras abaixo.

## Atualizar

Snapshot do LXC no Proxmox e depois `bash /opt/allfiltro/app/atualizar.sh`.

## Comandos

```sh
cd /opt/allfiltro/app
runuser -u allfiltro -- /opt/allfiltro/venv/bin/python -m allfiltro.cli status
runuser -u allfiltro -- /opt/allfiltro/venv/bin/python -m allfiltro.cli publicar     # gera versão agora
runuser -u allfiltro -- /opt/allfiltro/venv/bin/python -m allfiltro.cli ativar 42    # libera travada / volta versão
runuser -u allfiltro -- /opt/allfiltro/venv/bin/python -m allfiltro.cli criar-admin LOGIN "Nome"
runuser -u allfiltro -- /opt/allfiltro/venv/bin/python -m allfiltro.cli classificar www.exemplo.com.br   # categoria de um site
journalctl -fu allfiltro-worker     # downloads e versões
journalctl -fu allfiltro-app        # painel e API
```

## Painel (`/admin`)

| Tela | Para quê |
|---|---|
| **Início** | Versão ativa, totais, fontes com erro, versões travadas, protegidos barrados, firewalls sem consultar há 48 h. Botão **Publicar agora** |
| **Domínios e IPs** | Busca um site/IP: em quais categorias está, por causa de qual domínio pai, de qual fonte veio e as entradas manuais. Incluir, retirar, desfazer, importar em massa |
| **Categorias** | Lista com totais e origens; criar, renomear, desativar |
| **Sem categoria** | Sites acessados nos clientes que nenhuma categoria pega, do mais acessado para o menos (1, 7, 30 ou 90 dias). Marcar e **Classificar** numa categoria (vira inclusão manual) ou **Ignorar** |
| **Fontes** *(sistema)* | URL, formato, frequência, mapeamento lista da fonte → categoria, baixar agora |
| **Versões** *(sistema)* | Histórico; liberar versão travada; voltar para uma anterior |
| **Protegidos** *(sistema)* | O que fonte nenhuma pode colocar em categoria |
| **Países** *(sistema)* | Conta/chave da MaxMind (testar, salvar, apagar), situação de cada fonte e das listas de países e serviços, atualizar agora |
| **Pacote** *(sistema)* | Envia o `all-filtros.sh`; canal teste → promover para estável → os firewalls se atualizam de madrugada; canal de cada firewall |
| **Usuários** / **Auditoria** *(sistema)* | Técnicos e admins; quem fez o quê, quando e de onde |

Técnico: busca, inclui, retira e publica. Admin: também a área de sistema, que só abre das redes de `redes_sistema` (em `/etc/allfiltro/allfiltro.conf`).

## Como uma categoria é montada

```
fontes mapeadas − protegidos − retirados à mão + incluídos à mão
```

- **Domínio vale para os subdomínios.** A versão publicada remove os subdomínios já cobertos pelo pai (`espn.com` + `foo.espn.com` → `espn.com`): o firewall recebe a menor lista que bloqueia a mesma coisa.
- **Pouca memória.** A montagem é toda em disco (`sort` em arquivo, uma passada): a UT1 Adulto (~5 milhões de domínios) não entra inteira na memória, nem aqui nem, no futuro, no pfSense.
- **Retirar** um subdomínio cujo pai continua na categoria não tem efeito, e o painel avisa. Incluir à mão vence retirar e protegido.
- **Protegidos:** `*.gov.br` protege o domínio e todos os subdomínios; `google.com` protege só ele (assim `mail.google.com` ainda pode entrar em *E-mail pela web*). Faixas privadas e reservadas de IP também são protegidas.
- **Travas:** categoria que cresce ou encolhe mais de 30% **e** mais de 500 itens por mudança de fonte não é ativada; a versão fica *travada*, a anterior continua valendo e o Início mostra o alerta. Entradas manuais não passam por essa trava. A primeira carga de uma categoria vazia também não.
- **Fonte com erro** (HTTP ≠ 200, vazia, formato estranho) mantém o último retrato válido e tenta de novo a cada 30 min.
- Uma categoria que não mudou é reaproveitada da versão anterior (hard link), então gerar versão é rápido.

## Classificação dos sites acessados

O pfSense só baixa as categorias que alguma política usa. Para o relatório mostrar a categoria de **todo** site acessado (liberado ou bloqueado, por DNS ou proxy), o coletor do ALL Filtros 2.11+ pergunta à central (`POST /api/v1/classificar`).

- **Índice por versão** (`classificador.idx` na pasta da versão): todos os domínios de todas as categorias num arquivo ordenado, com busca binária. O worker monta no minuto seguinte a cada versão nova (uns 6 s para 6 milhões de domínios, ~120 MB). Enquanto isso a API usa o índice da versão anterior.
- Vale o **domínio mais específico** (`mail.google.com` antes de `google.com`). Site em mais de uma categoria: vale a privada do cliente, depois a menor categoria (mais específica). Categoria privada só para o cliente dono.
- **Protegidos** não entram em categoria por fonte, então `google.com`, `googleapis.com`, `microsoft.com`… ficam sem. Por isso a semente cria **Serviços e infraestrutura** (sistema, nuvem, CDN, antivírus) e **Buscadores**, só com inclusões manuais: servem para o relatório, não para bloquear.
- Sites sem categoria somam acessos na tabela `sem_categoria` (por site: `cdn.loja.com.br` → `loja.com.br`) e aparecem na tela **Sem categoria**. Classificado lá, entra na próxima versão; os firewalls perguntam de novo em até 12 h.

## Países e serviços (IPs)

Para a aba **Países** do ALL Filtros (entrada pelas WANs só de alguns países). O worker atualiza uma vez por dia (`/srv/allfiltro/redes`, `python -m allfiltro.cli redes [--forcar]`):

- **Registros oficiais** (LACNIC, ARIN, RIPE, APNIC, AFRINIC): onde o IP foi registrado. Sempre usados, sem chave.
- **MaxMind GeoLite2-Country**: onde o IP é usado (pega, por exemplo, a Starlink no Brasil), continentes e a lista *proxy anônimo e satélite*. Precisa de conta gratuita: no painel, **Sistema → Países**, informe o *Account ID* e uma *License Key* da MaxMind (**Testar e salvar** confere com a MaxMind antes de gravar; a chave fica em `/srv/allfiltro/redes/maxmind.json`, permissão 600, e não volta a aparecer na tela). Também vale `maxmind_conta`/`maxmind_chave` no `/etc/allfiltro/allfiltro.conf`. Sem elas, só os registros oficiais. **Atualizar agora** na mesma tela refaz as listas no próximo minuto.
- As duas fontes são **somadas** (um IP do Brasil em qualquer uma conta como Brasil).
- **Serviços**: faixas publicadas por Microsoft 365, Google, Google Cloud, AWS, Cloudflare e Starlink, para exceções prontas.
- Fonte com erro mantém o último download bom; lista do Brasil suspeita (quase vazia) não é publicada. A situação aparece no Início do painel.

## Contrato com o pfSense

| Requisição | O que faz |
|---|---|
| `GET /api/v1/manifest` | Manifesto da versão ativa (JSON). `ETag` → `304` sem mudança. Assinatura Ed25519 em base64 no cabeçalho `X-Assinatura-Ed25519` |
| `GET /api/v1/manifest.sig` | A mesma assinatura, em texto (para quem não lê cabeçalhos) |
| `GET /api/v1/cat/<chave>/dominios.txt.gz` | Domínios da categoria (`?v=N` para uma versão específica) |
| `GET /api/v1/cat/<chave>/ips.txt.gz` | IPs e faixas |
| `GET /api/v1/chave-publica` | Chave pública (PEM) — vai embutida no pacote |
| `GET /api/v1/pacote` | Última versão do pacote ALL Filtros para o canal do firewall (JSON assinado como o manifesto: versão, sha256, url) |
| `GET /api/v1/pacote/<versão>/all-filtros.sh` | O pacote (X-Sendfile) |
| `GET /instalar/all-filtros.sh` | Última estável, para a primeira instalação |
| `GET /api/v1/redes` | Listas de IP por país, continente e serviço (aba Países do ALL Filtros), manifesto assinado como o das categorias |
| `GET /api/v1/redes/<lista>.txt.gz` | Faixas (IPv4 e IPv6, CIDR) de `pais-br`, `continente-eu`, `satelite-proxy`, `servico-microsoft365`... |
| `GET /api/v1/licenca` | Situação da chave do cliente (assinada como o manifesto): status, validade, firewalls permitidos e se este firewall está aprovado |
| `POST /api/v1/classificar` | Corpo `{"dominios": {"site": acessos}}` (até 2000, com a chave do cliente). Resposta `{"versao": N, "categorias": {"site": ["Nome", …]}}`, lista vazia = sem categoria |

Cabeçalhos do pfSense: `Authorization: Bearer ALLF-…` (chave do cliente), `X-Firewall-Id`, `X-Pacote-Versao`, `X-Hostname`. Cada consulta atualiza o firewall no painel (Sistema → Clientes).

**Clientes e chaves.** Em *Sistema → Clientes* cada cliente ganha uma chave `ALLF-XXXXX-XXXXX-XXXXX-XXXXX`, mostrada uma única vez (a central guarda só o HMAC). Com a chave, o manifesto inclui as **categorias privadas** do cliente: crie em *Categorias* com tipo *privada* e marque os clientes. Sem chave, ou com a chave de outro cliente, a categoria privada não aparece e o arquivo responde 404. Firewall novo acima do limite da assinatura fica *aguardando* aprovação no painel.

**Licenciamento** (`licenciamento` em `/etc/allfiltro/allfiltro.conf`): `desligado` (padrão) — a chave só identifica o cliente; `ligado` — chave suspensa, cancelada ou vencida, ou firewall aguardando, deixa de receber as categorias privadas (as públicas continuam).

Arquivos: um item por linha, minúsculo, LF, UTF-8, gzip determinístico (o mesmo conteúdo sempre tem o mesmo sha256). Domínios sem `www.` e com acento em punycode; IPs como endereço ou CIDR.

Conferência no pfSense (o PHP do pfSense não tem sodium; o `openssl` de linha de comando tem Ed25519):

```sh
openssl pkeyutl -verify -rawin -pubin -inkey central.pub -in manifest.json -sigfile manifest.sig
sha256 -q dominios.txt.gz    # igual ao sha256 do manifesto
```

Exemplo de manifesto:

```json
{"categorias":{"esportes":{"descricao":"Sites de esportes e resultados","dominios":{"bytes":1234,"itens":5321,
 "sha256":"…","url":"/api/v1/cat/esportes/dominios.txt.gz"},"ips":{"bytes":20,"itens":0,"sha256":"…",
 "url":"/api/v1/cat/esportes/ips.txt.gz"},"nome":"Esportes","tipo":"publica"}},"central":"https://allfiltro.alltecnologias.com.br",
 "cliente":null,"formato":1,"gerado_em":"2026-11-03T18:00:00+00:00","versao":42}
```

## HAProxy (sugestão)

```
acl allfiltro       hdr(host) -i allfiltro.alltecnologias.com.br
acl allf_api        path_beg /api/
acl allf_login      path /admin/login
acl allf_sistema    path_beg /admin/sistema
acl rede_all        src 172.16.0.0/22 10.8.0.0/24          # escritório e VPN
http-request deny if allfiltro allf_sistema !rede_all       # quando quiser fechar
stick-table type ip size 100k expire 10m store http_req_rate(1m)
http-request track-sc0 src if allfiltro allf_api or allfiltro allf_login
http-request deny deny_status 429 if allfiltro allf_login { sc_http_req_rate(0) gt 20 }
http-request deny deny_status 429 if allfiltro allf_api { sc_http_req_rate(0) gt 120 }
http-request set-header X-Forwarded-For %[src]
http-request set-header X-Forwarded-Proto https if { ssl_fc }
timeout server 120s
```

## Diferenças do briefing

- O retrato das fontes fica em arquivos ordenados (`/srv/allfiltro/fontes`), não na tabela `itens_fonte`: milhões de linhas por download não cabem bem no banco e, em arquivo, a busca é binária e a montagem usa pouca memória.
- Apache com `mod_xsendfile` no lugar do nginx; LXC com systemd no lugar do stack do Portainer.
- Painel em Jinja2 sem HTMX (formulários simples; nenhum script externo).

## Desenvolvimento

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
ALLFILTRO_CONF=./teste.conf .venv/bin/alembic upgrade head
PYTHONPATH=. .venv/bin/pytest -q tests
```
