"""Dados iniciais: categorias da central, fonte UT1 mapeada e protegidos.

Idempotente: so cria o que falta (nao muda o que o tecnico ja editou).
"""
from sqlalchemy import select

from .models import Categoria, Fonte, Mapeamento, Protegido

UT1_URL = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"

# chave da central: (nome, descricao, pasta da UT1 ou None)
CATEGORIAS = {
    "acesso-remoto": ("Acesso remoto", "AnyDesk, TeamViewer e similares", "remote-control"),
    "adulto": ("Adulto", "Conteúdo adulto", "adult"),
    "apostas": ("Apostas", "Apostas esportivas e cassinos online", "gambling"),
    "associacoes-religiosas": ("Associações religiosas", "Sites de igrejas e grupos religiosos", "associations_religieuses"),
    "astrologia": ("Astrologia", "Horóscopo e esoterismo", "astrology"),
    "ataques-ddos": ("Ataques DDoS", "Serviços de ataque a outros sites e redes", "ddos"),
    "atualizacoes": ("Atualizações", "Windows Update e atualizações de programas", "update"),
    "bancos": ("Bancos", "Internet banking (só inclusão manual: bancos são protegidos)", None),
    "bate-papo": ("Bate-papo", "Salas de bate-papo e mensageiros como o Telegram", "chat"),
    "blogs": ("Blogs", "Blogs pessoais e de empresas", "blog"),
    "burla-de-filtro": ("Burla de filtro", "Proxies e anonimizadores usados para driblar o bloqueio", "redirector"),
    "vpn": ("VPN / anonimizador", "Sites e aplicativos de VPN usados para driblar o filtro", "vpn"),
    "celebridades": ("Celebridades", "Fofoca e notícias de famosos", "celebrity"),
    "compartilhamento-arquivos": ("Compartilhamento de arquivos", "Google Drive, Dropbox, WeTransfer e similares", "filehosting"),
    "compras": ("Compras online", "Lojas virtuais e marketplaces", "shopping"),
    "adulto-misto": ("Conteúdo misto adulto", "Sites com parte do conteúdo adulto", "mixed_adult"),
    "culinaria": ("Culinária", "Receitas e gastronomia", "cooking"),
    "downloads": ("Downloads de programas", "Sites de download de software", "download"),
    "drogas": ("Drogas", "Venda e uso de drogas", "drogue"),
    "webmail": ("E-mail pela web", "Gmail, Outlook e similares", "webmail"),
    "educacao-sexual": ("Educação sexual", "Saúde e educação sexual", "sexual_education"),
    "encurtadores": ("Encurtadores de link", "bit.ly e similares", "shortener"),
    "esportes": ("Esportes", "Sites de esportes e resultados", "sports"),
    "dinheiro-facil": ("Esquemas de dinheiro fácil", "Pirâmides, \"ganhe dinheiro\" e marketing duvidoso", "marketingware"),
    "foruns": ("Fóruns", "Fóruns de discussão", "forums"),
    "hacking": ("Hacking", "Ferramentas e conteúdo de invasão", "hacking"),
    "infantil": ("Infantil", "Sites para crianças", "child"),
    "jogos": ("Jogos", "Jogos online e sites de jogos", "games"),
    "jogos-educativos": ("Jogos educativos", "Jogos de aprendizado", "educational_games"),
    "lingerie": ("Lingerie", "Moda íntima", "lingerie"),
    "malware": ("Malware", "Sites com vírus e programas maliciosos", "malware"),
    "manga-anime": ("Mangá e anime", "Leitura de mangá e anime", "manga"),
    "material-perigoso": ("Material perigoso", "Armas e explosivos", "dangerous_material"),
    "mineracao-cripto": ("Mineração de criptomoeda", "Sites que usam o computador escondido para minerar moedas digitais", "bitcoin"),
    "namoro": ("Namoro", "Aplicativos e sites de relacionamento", "dating"),
    "noticias": ("Notícias", "Jornais e portais de notícias", "press"),
    "noticias-financeiras": ("Notícias financeiras", "Informações de mercado e finanças", "financial"),
    "odio-violencia": ("Ódio e violência", "Racismo, discriminação e incitação à violência", "agressif"),
    "personalizacao-celular": ("Personalização de celular", "Toques, papéis de parede e temas", "mobile-phone"),
    "phishing": ("Phishing", "Golpes e sites falsos que roubam senhas e dados", "phishing"),
    "pirataria": ("Pirataria", "Download de filmes, programas e jogos piratas", "warez"),
    "publicidade": ("Publicidade", "Anúncios em sites", "publicite"),
    "radios": ("Rádios online", "Rádios pela internet", "radio"),
    "redes-sociais": ("Redes sociais", "Instagram, Facebook, TikTok, X (Twitter), Kwai e similares", "social_networks"),
    "seitas": ("Seitas", "Grupos sectários", "sect"),
    "tradutores": ("Tradutores", "Google Tradutor e similares", "translation"),
    "trapaca": ("Trapaça", "Trapaça em jogos e provas", "tricheur"),
    "vagas-emprego": ("Vagas de emprego", "Sites de vagas", "jobsearch"),
    "video-musica": ("Vídeo e música", "YouTube, Netflix, Spotify e outros serviços de streaming", "audio-video"),
    "sistemas-fiscais": ("Sistemas fiscais", "SEFAZ, eSocial, Receita e emissores de nota (só inclusão manual)", None),
}

# "*.x" = x e todos os subdominios; "x" = so o proprio dominio
PROTEGIDOS_DOMINIOS = {
    "google.com": "Busca e login do Google (subdomínios como mail/drive seguem as categorias)",
    "accounts.google.com": "Login do Google",
    "*.gstatic.com": "Recursos de quase todo site",
    # googleapis.com: so os servicos que sites e aplicativos usam; os buckets
    # *.storage.googleapis.com hospedam golpes e podem entrar nas listas
    "googleapis.com": "APIs do Google",
    "www.googleapis.com": "APIs do Google",
    "fonts.googleapis.com": "Fontes usadas por quase todo site",
    "ajax.googleapis.com": "Bibliotecas usadas por sites",
    "maps.googleapis.com": "Google Maps em sites e sistemas",
    "storage.googleapis.com": "Armazenamento do Google (só o endereço principal)",
    "oauth2.googleapis.com": "Login com Google",
    "android.googleapis.com": "Serviços do Android",
    "update.googleapis.com": "Atualização do Chrome",
    "safebrowsing.googleapis.com": "Proteção contra golpes do navegador",
    "content.googleapis.com": "APIs do Google",
    "microsoft.com": "Site da Microsoft",
    "login.microsoftonline.com": "Login Microsoft 365",
    "*.windowsupdate.com": "Windows Update",
    "*.update.microsoft.com": "Windows Update",
    "office.com": "Microsoft 365",
    "office365.com": "Microsoft 365",
    "apple.com": "Site e atualizações da Apple",
    "*.gov.br": "Governo (inclui fazenda.gov.br, receita, eSocial)",
    "*.alltecnologias.com.br": "ALL Tecnologias",
    "*.alltecnologias.online": "ALL Tecnologias",
    "*.openvpn.com": "OpenVPN Connect (VPN do escritório)",
    "*.openvpn.net": "OpenVPN Connect (VPN do escritório)",
    "*.bb.com.br": "Banco do Brasil",
    "*.caixa.gov.br": "Caixa",
    "*.itau.com.br": "Itaú",
    "*.bradesco.com.br": "Bradesco",
    "*.santander.com.br": "Santander",
    "*.nubank.com.br": "Nubank",
    "*.sicoob.com.br": "Sicoob",
    "*.sicredi.com.br": "Sicredi",
    "*.bancointer.com.br": "Inter",
    "*.inter.co": "Inter",
    "*.c6bank.com.br": "C6 Bank",
    "*.btgpactual.com": "BTG Pactual",
}

PROTEGIDOS_IPS = {
    "10.0.0.0/8": "Rede privada", "172.16.0.0/12": "Rede privada", "192.168.0.0/16": "Rede privada",
    "100.64.0.0/10": "CGNAT", "127.0.0.0/8": "Loopback", "169.254.0.0/16": "Link-local",
    "0.0.0.0/8": "Reservado", "224.0.0.0/4": "Multicast", "240.0.0.0/4": "Reservado",
    "::1/128": "Loopback IPv6", "fe80::/10": "Link-local IPv6", "fc00::/7": "Rede privada IPv6",
}


# protegidos antigos da semente que foram trocados por outros
SUBSTITUIDOS = {"*.googleapis.com": "APIs usadas por sites e aplicativos"}


def semear(s) -> list:
    feito = []
    for valor, motivo in SUBSTITUIDOS.items():
        p = s.scalars(select(Protegido).where(Protegido.valor == valor)).first()
        if p is not None and p.motivo == motivo:  # so se ninguem editou
            s.delete(p)
            feito.append(f"protegido {valor} substituido")
    s.flush()
    existentes = {c.chave: c for c in s.scalars(select(Categoria)).all()}
    for chave, (nome, desc, _) in CATEGORIAS.items():
        if chave not in existentes:
            c = Categoria(chave=chave, nome=nome, descricao=desc, tipo="publica", ativa=True)
            s.add(c)
            existentes[chave] = c
            feito.append(f"categoria {chave}")
    s.flush()
    # pela URL ou pelo nome: o tecnico pode trocar a URL (espelho) sem duplicar a fonte
    ut1 = s.scalars(select(Fonte).where((Fonte.url == UT1_URL) | Fonte.nome.like("UT1%"))).first()
    if ut1 is None:
        ut1 = Fonte(nome="UT1 (Université Toulouse Capitole)", url=UT1_URL, formato="pacote", frequencia_h=24,
                    ativa=True, ultimo_status="", ultimo_sha256="", retrato_sha256="", baixar_agora=True)
        s.add(ut1)
        s.flush()
        feito.append("fonte UT1")
        for chave, (_, _, pasta) in CATEGORIAS.items():
            if pasta:
                s.add(Mapeamento(fonte_id=ut1.id, categoria_origem=pasta, categoria_id=existentes[chave].id))
        feito.append("mapeamentos UT1")
    vals = {p.valor for p in s.scalars(select(Protegido)).all()}
    for v, motivo in PROTEGIDOS_DOMINIOS.items():
        if v not in vals:
            s.add(Protegido(valor=v, tipo="dominio", motivo=motivo))
            feito.append(f"protegido {v}")
    for v, motivo in PROTEGIDOS_IPS.items():
        if v not in vals:
            s.add(Protegido(valor=v, tipo="ip", motivo=motivo))
    return feito
