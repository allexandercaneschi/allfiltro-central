"""Classificacao de sites: em que categoria esta um dominio (mesmo os liberados).

O pfSense so baixa as categorias que alguma politica usa; para classificar
qualquer site acessado ele pergunta a central, que tem todas.

Indice por versao (dir_versao(n)/classificador.idx): uma linha por dominio,
"rotulos invertidos<TAB>chave1,chave2", ordenado com LC_ALL=C. O TAB vem antes
de qualquer caractere valido, entao a ordem da linha inteira e a mesma ordem da
chave e a busca binaria funciona pela linha. As chaves de cada dominio ficam da
categoria mais especifica (menos itens) para a mais ampla; privadas primeiro.

Sites que nenhuma categoria pega ficam em "sem_categoria" (somando os acessos
que os firewalls informam) para o tecnico classificar no painel.
"""
import mmap
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from .arquivos import AMBIENTE_SORT
from .montagem import _inv, _prefixos_inv, dir_versao

NOME_INDICE = "classificador.idx"
MAX_POR_PEDIDO = 2000

# segundo nivel de dominios de pais (exemplo.com.br -> exemplo.com.br, nao com.br)
_SEGUNDO_NIVEL = {"com", "net", "org", "gov", "edu", "mil", "co", "ac", "art", "blog", "eco", "ind", "inf",
                  "srv", "tv", "app", "dev", "log", "rec", "adv", "arq", "eng", "med", "jus", "leg", "mp", "ne",
                  "or", "go", "gob", "nic"}


def site(dominio: str) -> str:
    """Dominio "registravel" (aproximado, sem lista de sufixos): www.loja.com.br -> loja.com.br."""
    p = dominio.split(".")
    if len(p) <= 2:
        return dominio
    if len(p[-1]) == 2 and p[-2] in _SEGUNDO_NIVEL:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


# --------------------------------------------------------------------------
# Indice
# --------------------------------------------------------------------------
def caminho_indice(numero: int) -> Path:
    return dir_versao(numero) / NOME_INDICE


def montar_indice(numero: int, manifesto: dict, tmpdir: Path) -> Path:
    """Junta os dominios de todas as categorias da versao num indice so."""
    base = dir_versao(numero)
    destino = base / NOME_INDICE
    cats = manifesto.get("categorias", {})
    # ordem das chaves dentro do dominio: privadas, depois as menores
    ordem = sorted(cats, key=lambda k: (cats[k].get("tipo") != "privada", cats[k]["dominios"]["itens"], k))
    pos = {k: i for i, k in enumerate(ordem)}
    tmpdir.mkdir(parents=True, exist_ok=True)
    bruto = tmpdir / f"classif-{numero}.bruto"
    ordenado = tmpdir / f"classif-{numero}.ord"
    try:
        with open(bruto, "w") as out:
            for chave in ordem:
                rev = base / "cat" / chave / "dominios.rev"
                if not rev.exists():
                    continue
                prefixo = f"\t{pos[chave]:04d}{chave}\n"
                with open(rev) as f:
                    for l in f:
                        l = l.rstrip("\n")
                        if l:
                            out.write(l + prefixo)
        subprocess.run(["sort", "-S", "256M", "-T", str(tmpdir), "-o", str(ordenado), str(bruto)],
                       check=True, env=AMBIENTE_SORT)
        bruto.unlink()
        novo = destino.with_suffix(".novo")
        with open(ordenado) as fi, open(novo, "w") as fo:
            atual, chaves = None, []
            for l in fi:
                dom, ch = l.rstrip("\n").split("\t", 1)
                ch = ch[4:]  # tira a posicao (so serviu para ordenar)
                if dom != atual:
                    if atual is not None:
                        fo.write(f"{atual}\t{','.join(chaves)}\n")
                    atual, chaves = dom, []
                if ch not in chaves:
                    chaves.append(ch)
            if atual is not None:
                fo.write(f"{atual}\t{','.join(chaves)}\n")
        os.chmod(novo, 0o644)
        novo.rename(destino)
    finally:
        bruto.unlink(missing_ok=True)
        ordenado.unlink(missing_ok=True)
    return destino


class Indice:
    """Busca binaria no indice mapeado em memoria (o SO cuida do cache)."""

    def __init__(self, caminho: Path):
        self.f = open(caminho, "rb")
        self.m = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ) if caminho.stat().st_size else None

    def fechar(self):
        if self.m is not None:
            self.m.close()
        self.f.close()

    def _linha(self, p):
        """Primeira linha inteira que comeca em p ou depois: (inicio, chave, valor)."""
        m = self.m
        if p > 0 and m[p - 1:p] != b"\n":
            q = m.find(b"\n", p)
            if q < 0:
                return None
            p = q + 1
        if p >= len(m):
            return None
        fim = m.find(b"\n", p)
        fim = len(m) if fim < 0 else fim
        dom, _, val = m[p:fim].partition(b"\t")
        return dom, val

    def buscar(self, chave_inv: str):
        if self.m is None:
            return None
        alvo = chave_inv.encode()
        lo, hi = 0, len(self.m)
        while lo < hi:
            meio = (lo + hi) // 2
            l = self._linha(meio)
            if l is None or l[0] >= alvo:
                hi = meio
            else:
                lo = meio + 1
        l = self._linha(lo)
        if l is not None and l[0] == alvo:
            return l[1].decode().split(",")
        return None


def classificar(numero: int, manifesto: dict, dominios, cliente_id: str | None) -> dict:
    """{dominio: [nome da categoria, ...]} (lista vazia = sem categoria).

    Vale o dominio mais especifico que estiver no indice (ex.: mail.google.com
    antes de google.com); categoria privada so para o cliente dela."""
    cats = manifesto.get("categorias", {})

    def visivel(ch):
        c = cats.get(ch)
        if c is None:
            return False
        return c.get("tipo") != "privada" or (cliente_id is not None and cliente_id in c.get("clientes", []))

    idx = Indice(caminho_indice(numero))
    try:
        res = {}
        for d in dominios:
            achou = []
            for p in reversed(list(_prefixos_inv(_inv(d)))):
                if " " not in p:
                    break  # so o TLD ("com") nunca classifica
                chaves = idx.buscar(p)
                if chaves:
                    achou = [cats[c]["nome"] for c in chaves if visivel(c)]
                    if achou:
                        break
            res[d] = achou
        return res
    finally:
        idx.fechar()


# --------------------------------------------------------------------------
# Sites sem categoria (para classificar no painel)
# --------------------------------------------------------------------------
def registrar_sem_categoria(s, contagem: dict, cliente_id: str | None):
    """Soma os acessos dos sites que ficaram sem categoria (por site, nao subdominio)."""
    por_site = {}
    for d, n in contagem.items():
        k = site(d)
        por_site[k] = por_site.get(k, 0) + max(1, int(n or 0))
    if not por_site:
        return
    agora = datetime.now(timezone.utc)
    s.execute(text("""
        INSERT INTO sem_categoria (dominio, acessos, clientes, primeiro_em, ultimo_em)
        VALUES (:d, :n, CASE WHEN CAST(:c AS text) IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(CAST(:c AS text)) END, :t, :t)
        ON CONFLICT (dominio) DO UPDATE SET
            acessos = sem_categoria.acessos + EXCLUDED.acessos,
            ultimo_em = EXCLUDED.ultimo_em,
            clientes = CASE WHEN CAST(:c AS text) IS NULL OR sem_categoria.clientes ? CAST(:c AS text) THEN sem_categoria.clientes
                            ELSE sem_categoria.clientes || jsonb_build_array(CAST(:c AS text)) END
    """), [{"d": k[:300], "n": n, "c": cliente_id, "t": agora} for k, n in sorted(por_site.items())])


def garantir_indice(s) -> str:
    """Monta o indice da versao ativa se ainda nao existe (roda no ciclo)."""
    from .config import config
    from .montagem import versao_ativa
    v = versao_ativa(s)
    if v is None or not dir_versao(v.versao).exists():
        return "sem versao"
    if caminho_indice(v.versao).exists():
        return "ok"
    montar_indice(v.versao, v.manifesto or {}, config().dir_tmp)
    return f"indice da versao {v.versao} montado"


def versao_com_indice(s):
    """Versao mais nova (ativa ou anterior) que ja tem indice."""
    from sqlalchemy import select
    from .models import Versao
    for v in s.scalars(select(Versao).where(Versao.status.in_(("ativa", "anterior")))
                       .order_by((Versao.status == "ativa").desc(), Versao.versao.desc())).all():
        if caminho_indice(v.versao).exists():
            return v
    return None
